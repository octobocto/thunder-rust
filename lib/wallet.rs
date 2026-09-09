use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use byteorder::{BigEndian, ByteOrder};
use ed25519_dalek_bip32::{ChildIndex, DerivationPath, ExtendedSigningKey};
use fallible_iterator::FallibleIterator as _;
use futures::{Stream, StreamExt};
use heed::types::{Bytes, SerdeBincode, U8};
use sneed::{Env, EnvError, RwTxnError, UnitKey, db::error::Error as DbError};
use tokio_stream::{StreamMap, wrappers::WatchStream};

use crate::{
    types::{
        Accumulator, Address, AmountOverflowError, AmountUnderflowError,
        AuthorizedTransaction, GetValue, InPoint, OutPoint, OutPointKey,
        Output, OutputContent, PointedOutput, SpentOutput, Transaction,
        UtreexoError, UtreexoNodeHash, VERSION, Version,
        authorization::{Authorization, get_address},
        hash,
        wallet::Balance,
    },
    util::Watchable,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("address {address} does not exist")]
    AddressDoesNotExist { address: crate::types::Address },
    #[error(transparent)]
    AmountOverflow(#[from] AmountOverflowError),
    #[error(transparent)]
    AmountUnderflow(#[from] AmountUnderflowError),
    #[error("authorization error")]
    Authorization(#[from] crate::types::error::Authorization),
    #[error("bip32 error")]
    Bip32(#[from] ed25519_dalek_bip32::Error),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("Database env error")]
    DbEnv(#[from] EnvError),
    #[error("Database write error")]
    DbWrite(#[from] RwTxnError),
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[error("no index for address {address}")]
    NoIndex { address: Address },
    #[error(
        "wallet does not have a seed (set with RPC `set-seed-from-mnemonic`)"
    )]
    NoSeed,
    #[error("not enough funds")]
    NotEnoughFunds,
    #[error("no transfer destination")]
    NoTransferDestination,
    #[error("utxo does not exist")]
    NoUtxo,
    #[error("failed to parse mnemonic seed phrase")]
    ParseMnemonic(#[source] bip39::ErrorKind),
    #[error("seed has already been set")]
    SeedAlreadyExists,
    #[error(transparent)]
    Utreexo(#[from] UtreexoError),
}

/// Marker type for Wallet Env
pub struct WalletEnv;

type DatabaseUnique<KC, DC> = sneed::DatabaseUnique<KC, DC, WalletEnv>;
type RoTxn<'a> = sneed::RoTxn<'a, heed::AnyTls, WalletEnv>;

#[derive(Clone)]
pub struct Wallet {
    env: sneed::Env<heed::WithoutTls, WalletEnv>,
    // Seed is always [u8; 64], but due to serde not implementing serialize
    // for [T; 64], use heed's `Bytes`
    // TODO: Don't store the seed in plaintext.
    seed: DatabaseUnique<U8, Bytes>,
    /// Map each address to it's index
    address_to_index:
        DatabaseUnique<SerdeBincode<Address>, SerdeBincode<[u8; 4]>>,
    /// Map each address index to an address
    index_to_address:
        DatabaseUnique<SerdeBincode<[u8; 4]>, SerdeBincode<Address>>,
    utxos: DatabaseUnique<OutPointKey, SerdeBincode<Output>>,
    stxos: DatabaseUnique<OutPointKey, SerdeBincode<SpentOutput>>,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl Wallet {
    pub const NUM_DBS: u32 = 6;

    pub fn new(path: &Path) -> Result<Self, Error> {
        std::fs::create_dir_all(path)?;
        let env = {
            use heed::EnvFlags;
            let mut env_open_options =
                heed::EnvOpenOptions::new().read_txn_without_tls();
            env_open_options
                // The wallet keeps every spent output, so a node that bids
                // for every mainchain block fills 10MB in weeks.
                .map_size(1024 * 1024 * 1024) // 1GB
                .max_dbs(Self::NUM_DBS);
            // Apply LMDB "fast" flags consistent with our benchmark setup:
            // - WRITE_MAP lets us write directly into the memory map instead of
            //   copying into LMDB's page buffer, reducing syscall overhead for
            //   write-heavy workloads.
            // - MAP_ASYNC hands dirty-page flushing to the kernel so commits do
            //   not block waiting for msync, keeping latencies tight.
            // - NO_SYNC and NO_META_SYNC skip fsync calls for data and
            //   metadata; this trades durability for throughput, which is
            //   acceptable here because the state can be reconstructed from the
            //   canonical chain if a crash occurs.
            // - NO_READ_AHEAD disables kernel readahead that would otherwise
            //   touch cold pages we immediately overwrite, improving random
            //   access behaviour on SSDs used in testing.
            // - NO_TLS stops LMDB from relying on thread-local storage for
            //   reader slots so transactions can be moved across Tokio tasks.
            let fast_flags = EnvFlags::WRITE_MAP
                | EnvFlags::MAP_ASYNC
                | EnvFlags::NO_SYNC
                | EnvFlags::NO_META_SYNC
                | EnvFlags::NO_READ_AHEAD;
            unsafe { env_open_options.flags(fast_flags) };
            unsafe { Env::open(&env_open_options, path) }
                .map_err(EnvError::from)?
        };
        let mut rwtxn = env.write_txn().map_err(EnvError::from)?;
        let seed_db = DatabaseUnique::create(&env, &mut rwtxn, "seed")
            .map_err(EnvError::from)?;
        let address_to_index =
            DatabaseUnique::create(&env, &mut rwtxn, "address_to_index")
                .map_err(EnvError::from)?;
        let index_to_address =
            DatabaseUnique::create(&env, &mut rwtxn, "index_to_address")
                .map_err(EnvError::from)?;
        let utxos = DatabaseUnique::create(&env, &mut rwtxn, "utxos")
            .map_err(EnvError::from)?;
        let stxos = DatabaseUnique::create(&env, &mut rwtxn, "stxos")
            .map_err(EnvError::from)?;
        let version = DatabaseUnique::create(&env, &mut rwtxn, "version")
            .map_err(EnvError::from)?;
        if version
            .try_get(&rwtxn, &())
            .map_err(DbError::from)?
            .is_none()
        {
            version
                .put(&mut rwtxn, &(), &*VERSION)
                .map_err(DbError::from)?;
        }
        rwtxn.commit().map_err(RwTxnError::from)?;
        let wallet = Self {
            env,
            seed: seed_db,
            address_to_index,
            index_to_address,
            utxos,
            stxos,
            _version: version,
        };
        let mut txn = wallet.env.write_txn().map_err(EnvError::from)?;
        wallet.recover_legacy_addresses(&mut txn)?;
        txn.commit().map_err(RwTxnError::from)?;
        Ok(wallet)
    }

    fn recover_legacy_addresses(
        &self,
        txn: &mut sneed::RwTxn<'_, WalletEnv>,
    ) -> Result<(), Error> {
        if self.seed.try_get(txn, &0).map_err(DbError::from)?.is_none() {
            return Ok(());
        }
        // The Go wallet used indices 0–499 without a native address record.
        for index in 0..500u32 {
            let key = index.to_be_bytes();
            if self
                .index_to_address
                .try_get(txn, &key)
                .map_err(DbError::from)?
                .is_some()
            {
                continue;
            }
            let signing_key = self.get_signing_key(txn, index)?;
            let address = get_address(&signing_key.verifying_key());
            self.index_to_address
                .put(txn, &key, &address)
                .map_err(DbError::from)?;
            self.address_to_index
                .put(txn, &address, &key)
                .map_err(DbError::from)?;
        }
        Ok(())
    }

    /// Overwrite the seed, or set it if it does not already exist.
    pub fn overwrite_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        let mut rwtxn = self.env.write_txn().map_err(EnvError::from)?;
        self.seed.put(&mut rwtxn, &0, seed).map_err(DbError::from)?;
        self.address_to_index
            .clear(&mut rwtxn)
            .map_err(DbError::from)?;
        self.index_to_address
            .clear(&mut rwtxn)
            .map_err(DbError::from)?;
        self.utxos.clear(&mut rwtxn).map_err(DbError::from)?;
        self.stxos.clear(&mut rwtxn).map_err(DbError::from)?;
        self.recover_legacy_addresses(&mut rwtxn)?;
        rwtxn.commit().map_err(RwTxnError::from)?;
        Ok(())
    }

    pub fn has_seed(&self) -> Result<bool, Error> {
        let rotxn = self.env.read_txn().map_err(EnvError::from)?;
        Ok(self
            .seed
            .try_get(&rotxn, &0)
            .map_err(DbError::from)?
            .is_some())
    }

    /// Set the seed, if it does not already exist
    pub fn set_seed(&self, seed: &[u8; 64]) -> Result<(), Error> {
        let rotxn = self.env.read_txn().map_err(EnvError::from)?;
        match self.seed.try_get(&rotxn, &0).map_err(DbError::from)? {
            Some(current_seed) => {
                if current_seed == seed {
                    Ok(())
                } else {
                    Err(Error::SeedAlreadyExists)
                }
            }
            None => {
                drop(rotxn);
                self.overwrite_seed(seed)
            }
        }
    }

    /// Set the seed from a mnemonic seed phrase,
    /// if the seed does not already exist
    pub fn set_seed_from_mnemonic(&self, mnemonic: &str) -> Result<(), Error> {
        let mnemonic =
            bip39::Mnemonic::from_phrase(mnemonic, bip39::Language::English)
                .map_err(Error::ParseMnemonic)?;
        let seed = bip39::Seed::new(&mnemonic, "");
        let seed_bytes: [u8; 64] = seed.as_bytes().try_into().unwrap();
        self.set_seed(&seed_bytes)
    }

    pub fn create_withdrawal(
        &self,
        accumulator: &Accumulator,
        main_address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        value: bitcoin::Amount,
        main_fee: bitcoin::Amount,
        fee: bitcoin::Amount,
    ) -> Result<Transaction, Error> {
        tracing::trace!(
            accumulator = %accumulator.0,
            fee = %fee.display_dynamic(),
            ?main_address,
            main_fee = %main_fee.display_dynamic(),
            value = %value.display_dynamic(),
            "Creating withdrawal"
        );
        let (total, coins) = self.select_coins(
            value
                .checked_add(fee)
                .ok_or(AmountOverflowError)?
                .checked_add(main_fee)
                .ok_or(AmountOverflowError)?,
        )?;
        let change = total - value - fee - main_fee;

        let inputs: Vec<_> = coins
            .into_iter()
            .map(|(outpoint, output)| {
                let utxo_hash = hash(&PointedOutput { outpoint, output });
                (outpoint, utxo_hash)
            })
            .collect();
        let input_utxo_hashes: Vec<UtreexoNodeHash> =
            inputs.iter().map(|(_, hash)| hash.into()).collect();
        let proof = accumulator.prove(&input_utxo_hashes)?;
        let outputs = vec![
            Output {
                address: self.get_new_address()?,
                content: OutputContent::Withdrawal {
                    value,
                    main_fee,
                    main_address,
                },
            },
            Output {
                address: self.get_new_address()?,
                content: OutputContent::Value(change),
            },
        ];
        Ok(Transaction {
            inputs,
            proof,
            outputs,
        })
    }

    pub fn create_transaction(
        &self,
        accumulator: &Accumulator,
        address: Address,
        value: bitcoin::Amount,
        fee: bitcoin::Amount,
    ) -> Result<Transaction, Error> {
        self.create_transaction_many(
            accumulator,
            &BTreeMap::from([(address, value)]),
            fee,
        )
    }

    /// Pay each address in `dests`, and pay the change to a new address
    pub fn create_transaction_many(
        &self,
        accumulator: &Accumulator,
        dests: &BTreeMap<Address, bitcoin::Amount>,
        fee: bitcoin::Amount,
    ) -> Result<Transaction, Error> {
        if dests.is_empty() {
            return Err(Error::NoTransferDestination);
        }
        let value = dests
            .values()
            .try_fold(bitcoin::Amount::ZERO, |total, value| {
                total.checked_add(*value)
            })
            .ok_or(AmountOverflowError)?;
        let (total, coins) = self
            .select_coins(value.checked_add(fee).ok_or(AmountOverflowError)?)?;
        let change = total - value - fee;
        let inputs: Vec<_> = coins
            .into_iter()
            .map(|(outpoint, output)| {
                let utxo_hash = hash(&PointedOutput { outpoint, output });
                (outpoint, utxo_hash)
            })
            .collect();
        let input_utxo_hashes: Vec<UtreexoNodeHash> =
            inputs.iter().map(|(_, hash)| hash.into()).collect();
        let proof = accumulator.prove(&input_utxo_hashes)?;
        let mut outputs: Vec<Output> = dests
            .iter()
            .map(|(address, value)| Output {
                address: *address,
                content: OutputContent::Value(*value),
            })
            .collect();
        outputs.push(Output {
            address: self.get_new_address()?,
            content: OutputContent::Value(change),
        });
        Ok(Transaction {
            inputs,
            proof,
            outputs,
        })
    }

    pub fn select_coins(
        &self,
        value: bitcoin::Amount,
    ) -> Result<(bitcoin::Amount, HashMap<OutPoint, Output>), Error> {
        use rayon::prelude::ParallelSliceMut;
        let rotxn = self.env.read_txn().map_err(EnvError::from)?;
        let mut utxos: Vec<_> = self
            .utxos
            .iter(&rotxn)
            .map_err(DbError::from)?
            .collect()
            .map_err(DbError::from)?;
        utxos.par_sort_unstable_by_key(|(_, output)| output.get_value());

        let mut selected = HashMap::new();
        let mut total = bitcoin::Amount::ZERO;
        for (outpoint_key, output) in &utxos {
            if output.content.is_withdrawal() {
                continue;
            }
            if total > value {
                break;
            }
            total = total
                .checked_add(output.get_value())
                .ok_or(AmountOverflowError)?;
            let outpoint: OutPoint = outpoint_key.into();
            selected.insert(outpoint, output.clone());
        }
        if total < value {
            return Err(Error::NotEnoughFunds);
        }
        Ok((total, selected))
    }

    pub fn delete_utxos(&self, outpoints: &[OutPoint]) -> Result<(), Error> {
        let mut txn = self.env.write_txn().map_err(EnvError::from)?;
        for outpoint in outpoints {
            let key = OutPointKey::from(outpoint);
            self.utxos.delete(&mut txn, &key).map_err(DbError::from)?;
        }
        txn.commit().map_err(RwTxnError::from)?;
        Ok(())
    }

    pub fn spend_utxos(
        &self,
        spent: &[(OutPoint, InPoint)],
    ) -> Result<(), Error> {
        let mut txn = self.env.write_txn().map_err(EnvError::from)?;
        for (outpoint, inpoint) in spent {
            let key = OutPointKey::from(outpoint);
            let output =
                self.utxos.try_get(&txn, &key).map_err(DbError::from)?;
            if let Some(output) = output {
                self.utxos.delete(&mut txn, &key).map_err(DbError::from)?;
                let spent_output = SpentOutput {
                    output,
                    inpoint: *inpoint,
                };
                self.stxos
                    .put(&mut txn, &key, &spent_output)
                    .map_err(DbError::from)?;
            }
        }
        txn.commit().map_err(RwTxnError::from)?;
        Ok(())
    }

    pub fn put_utxos(
        &self,
        utxos: &HashMap<OutPoint, Output>,
    ) -> Result<(), Error> {
        let mut txn = self.env.write_txn().map_err(EnvError::from)?;
        for (outpoint, output) in utxos {
            let key = OutPointKey::from(outpoint);
            self.utxos
                .put(&mut txn, &key, output)
                .map_err(DbError::from)?;
        }
        txn.commit().map_err(RwTxnError::from)?;
        Ok(())
    }

    pub fn get_balance(&self) -> Result<Balance, Error> {
        let mut balance = Balance::default();
        let txn = self.env.read_txn().map_err(EnvError::from)?;
        let () = self
            .utxos
            .iter(&txn)
            .map_err(DbError::from)?
            .map_err(|err| DbError::from(err).into())
            .for_each(|(_, utxo)| {
                let value = utxo.get_value();
                balance.total = balance
                    .total
                    .checked_add(value)
                    .ok_or(AmountOverflowError)?;
                if !utxo.content.is_withdrawal() {
                    balance.available = balance
                        .available
                        .checked_add(value)
                        .ok_or(AmountOverflowError)?;
                }
                Ok::<_, Error>(())
            })?;
        Ok(balance)
    }

    pub fn get_utxos(&self) -> Result<HashMap<OutPoint, Output>, Error> {
        let rotxn = self.env.read_txn().map_err(EnvError::from)?;
        let utxos: HashMap<OutPoint, Output> = self
            .utxos
            .iter(&rotxn)
            .map_err(DbError::from)?
            .map(|(key, output)| Ok((key.into(), output)))
            .collect()
            .map_err(DbError::from)?;
        Ok(utxos)
    }

    pub fn get_addresses(&self) -> Result<HashSet<Address>, Error> {
        let rotxn = self.env.read_txn().map_err(EnvError::from)?;
        let addresses: HashSet<_> = self
            .index_to_address
            .iter(&rotxn)
            .map_err(DbError::from)?
            .map(|(_, address)| Ok(address))
            .collect()
            .map_err(DbError::from)?;
        Ok(addresses)
    }

    pub fn authorize(
        &self,
        transaction: Transaction,
    ) -> Result<AuthorizedTransaction, Error> {
        let txn = self.env.read_txn().map_err(EnvError::from)?;
        let mut authorizations = Vec::with_capacity(transaction.inputs.len());
        for (outpoint, _) in &transaction.inputs {
            let key = OutPointKey::from(outpoint);
            let spent_utxo = self
                .utxos
                .try_get(&txn, &key)
                .map_err(DbError::from)?
                .ok_or(Error::NoUtxo)?;
            let index = self
                .address_to_index
                .try_get(&txn, &spent_utxo.address)
                .map_err(DbError::from)?
                .ok_or(Error::NoIndex {
                    address: spent_utxo.address,
                })?;
            let index = BigEndian::read_u32(&index);
            let signing_key = self.get_signing_key(&txn, index)?;
            let signature =
                crate::types::authorization::sign(&signing_key, &transaction)?;
            authorizations.push(Authorization {
                verifying_key: signing_key.verifying_key(),
                signature,
            });
        }
        Ok(AuthorizedTransaction {
            authorizations,
            transaction,
        })
    }

    /// Derives an address the wallet never used. A change output takes one of
    /// these, so two transactions never share a change address.
    pub fn get_new_address(&self) -> Result<Address, Error> {
        let mut txn = self.env.write_txn().map_err(EnvError::from)?;
        let index =
            match self.index_to_address.last(&txn).map_err(DbError::from)? {
                Some((last_index, _)) => BigEndian::read_u32(&last_index) + 1,
                None => 0,
            };
        let signing_key = self.get_signing_key(&txn, index)?;
        let address = get_address(&signing_key.verifying_key());
        let index = index.to_be_bytes();
        self.index_to_address
            .put(&mut txn, &index, &address)
            .map_err(DbError::from)?;
        self.address_to_index
            .put(&mut txn, &address, &index)
            .map_err(DbError::from)?;
        txn.commit().map_err(RwTxnError::from)?;
        Ok(address)
    }

    /// The address to receive at. Derives a new one only once the current one
    /// receives.
    pub fn get_receive_address(&self) -> Result<Address, Error> {
        {
            let rotxn = self.env.read_txn().map_err(EnvError::from)?;
            let last =
                self.index_to_address.last(&rotxn).map_err(DbError::from)?;
            if let Some((_, address)) = last
                && !self.address_received(&rotxn, &address)?
            {
                return Ok(address);
            }
        }
        self.get_new_address()
    }

    /// True when any output the wallet holds or held pays this address.
    fn address_received(
        &self,
        rotxn: &RoTxn,
        address: &Address,
    ) -> Result<bool, Error> {
        let mut utxos = self.utxos.iter(rotxn).map_err(DbError::from)?;
        while let Some((_, output)) = utxos.next().map_err(DbError::from)? {
            if output.address == *address {
                return Ok(true);
            }
        }
        let mut stxos = self.stxos.iter(rotxn).map_err(DbError::from)?;
        while let Some((_, spent)) = stxos.next().map_err(DbError::from)? {
            if spent.output.address == *address {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Gets the latest generated address.
    pub fn try_get_last_address(&self) -> Result<Option<Address>, Error> {
        let txn = self.env.read_txn().map_err(EnvError::from)?;
        let last = self.index_to_address.last(&txn).map_err(DbError::from)?;
        Ok(last.map(|(_, address)| address))
    }

    /// Gets the latest generated address, or generates a new one if no
    /// addresses have already been generated.
    pub fn get_or_generate_last_address(&self) -> Result<Address, Error> {
        if let Some(address) = self.try_get_last_address()? {
            Ok(address)
        } else {
            self.get_new_address()
        }
    }

    pub fn get_num_addresses(&self) -> Result<u32, Error> {
        let txn = self.env.read_txn().map_err(EnvError::from)?;
        let num = self.index_to_address.len(&txn).map_err(DbError::from)?;
        Ok(num as u32)
    }

    fn get_signing_key(
        &self,
        rotxn: &RoTxn,
        index: u32,
    ) -> Result<ed25519_dalek::SigningKey, Error> {
        let seed = self
            .seed
            .try_get(rotxn, &0)
            .map_err(DbError::from)?
            .ok_or(Error::NoSeed)?;
        let xpriv = ExtendedSigningKey::from_seed(seed)?;
        let derivation_path = DerivationPath::new([
            ChildIndex::Hardened(1),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(0),
            ChildIndex::Hardened(index),
        ]);
        let xsigning_key = xpriv.derive(&derivation_path)?;
        Ok(xsigning_key.signing_key)
    }
}

impl Watchable<()> for Wallet {
    type WatchStream = std::pin::Pin<Box<dyn Stream<Item = ()> + Send>>;

    /// Get a signal that notifies whenever the wallet changes
    fn watch(&self) -> Self::WatchStream {
        let Self {
            env: _,
            seed,
            address_to_index,
            index_to_address,
            utxos,
            stxos,
            _version: _,
        } = self;
        let watchables = [
            seed.watch().clone(),
            address_to_index.watch().clone(),
            index_to_address.watch().clone(),
            utxos.watch().clone(),
            stxos.watch().clone(),
        ];
        let streams = StreamMap::from_iter(
            watchables.into_iter().map(WatchStream::new).enumerate(),
        );
        let streams_len = streams.len();
        Box::pin(streams.ready_chunks(streams_len).map(|signals| {
            assert_ne!(signals.len(), 0);
            #[allow(clippy::unused_unit)]
            ()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn scan_legacy_change(wallet: &Wallet) -> anyhow::Result<()> {
        use crate::state::State;

        let dir = temp_dir::TempDir::new()?;
        let env = unsafe {
            sneed::Env::open(
                heed::EnvOpenOptions::new().max_dbs(State::NUM_DBS),
                dir.path(),
            )?
        };
        let state = State::new(&env)?;
        let output: Output = serde_json::from_str(
            r#"{"address":"23xexovKLYvj8qWhpNBEo828eWQS","content":{"Value":5500}}"#,
        )?;
        let point = OutPoint::Regular {
            txid: [0xab; 32].into(),
            vout: 1,
        };
        let mut txn = env.write_txn()?;
        state
            .utxos
            .put(&mut txn, &OutPointKey::from(&point), &output)?;
        txn.commit()?;
        let txn = env.read_txn()?;
        let found =
            state.get_utxos_by_addresses(&txn, &wallet.get_addresses()?)?;
        wallet.put_utxos(&found)?;
        Ok(())
    }

    #[test]
    fn test_legacy_change_after_seed_import() -> anyhow::Result<()> {
        let dir = temp_dir::TempDir::new()?;
        let wallet = Wallet::new(dir.path())?;
        assert!(!wallet.has_seed()?);
        assert!(wallet.get_addresses()?.is_empty());
        wallet.set_seed_from_mnemonic(LEGACY_MNEMONIC)?;

        scan_legacy_change(&wallet)?;
        assert_eq!(wallet.get_balance()?.total.to_sat(), 5500);
        assert_eq!(wallet.get_num_addresses()?, 500);
        assert!(
            wallet
                .get_addresses()?
                .contains(&"38VvRdmcQREr1UAcZma98WLFVpAp".parse()?)
        );

        let (point, output) = wallet.get_utxos()?.into_iter().next().unwrap();
        let signed = wallet.authorize(Transaction {
            inputs: vec![(
                point,
                hash(&PointedOutput {
                    outpoint: point,
                    output: output.clone(),
                }),
            )],
            outputs: vec![output.clone()],
            ..Transaction::default()
        })?;
        crate::types::authorization::verify_authorized_transaction(&signed)?;
        assert_eq!(
            get_address(&signed.authorizations[0].verifying_key),
            output.address
        );
        Ok(())
    }

    #[test]
    fn test_legacy_recovery_keeps_seed_and_addresses() -> anyhow::Result<()> {
        let dir = temp_dir::TempDir::new()?;
        let addresses = {
            let wallet = Wallet::new(dir.path())?;
            wallet.set_seed_from_mnemonic(LEGACY_MNEMONIC)?;
            scan_legacy_change(&wallet)?;
            let addresses = wallet.get_addresses()?;
            assert_eq!(addresses.len(), 500);
            wallet.set_seed_from_mnemonic(LEGACY_MNEMONIC)?;
            assert_eq!(wallet.get_addresses()?, addresses);
            assert!(matches!(
                wallet.set_seed(&[2; 64]),
                Err(Error::SeedAlreadyExists)
            ));
            assert_eq!(wallet.get_addresses()?, addresses);
            assert_eq!(wallet.get_balance()?.total.to_sat(), 5500);
            addresses
        };
        for _ in 0..2 {
            let wallet = Wallet::new(dir.path())?;
            assert_eq!(wallet.get_addresses()?, addresses);
            assert_eq!(wallet.get_balance()?.total.to_sat(), 5500);
        }
        Ok(())
    }

    #[test]
    fn test_legacy_recovery_keeps_existing_wallet() -> anyhow::Result<()> {
        let dir = temp_dir::TempDir::new()?;
        let (last_address, next_address) = {
            let wallet = Wallet::new(dir.path())?;
            wallet.set_seed_from_mnemonic(LEGACY_MNEMONIC)?;
            let mut txn = wallet.env.write_txn()?;
            wallet.index_to_address.clear(&mut txn)?;
            wallet.address_to_index.clear(&mut txn)?;
            let mut last_address = Address([0; 20]);
            for index in [1u32, 600] {
                let address = get_address(
                    &wallet.get_signing_key(&txn, index)?.verifying_key(),
                );
                let key = index.to_be_bytes();
                wallet.index_to_address.put(&mut txn, &key, &address)?;
                wallet.address_to_index.put(&mut txn, &address, &key)?;
                last_address = address;
            }
            let next_address = get_address(
                &wallet.get_signing_key(&txn, 601)?.verifying_key(),
            );
            txn.commit()?;
            wallet.put_utxos(&HashMap::from([(
                OutPoint::Regular {
                    txid: [1; 32].into(),
                    vout: 0,
                },
                Output {
                    address: last_address,
                    content: OutputContent::Value(bitcoin::Amount::from_sat(
                        1000,
                    )),
                },
            )]))?;
            assert_eq!(wallet.get_num_addresses()?, 2);
            (last_address, next_address)
        };

        let wallet = Wallet::new(dir.path())?;
        assert_eq!(wallet.get_num_addresses()?, 501);
        assert!(wallet.get_addresses()?.contains(&last_address));
        assert!(
            wallet
                .get_addresses()?
                .contains(&"38VvRdmcQREr1UAcZma98WLFVpAp".parse()?)
        );
        assert_eq!(wallet.get_balance()?.total.to_sat(), 1000);
        scan_legacy_change(&wallet)?;
        assert_eq!(wallet.get_balance()?.total.to_sat(), 6500);
        assert_eq!(wallet.get_new_address()?, next_address);
        assert_eq!(wallet.get_num_addresses()?, 502);
        Ok(())
    }

    #[test]
    fn test_get_receive_address() -> anyhow::Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("thunder_test_receive_{nanos}"));
        if test_dir.exists() {
            let _unused = std::fs::remove_dir_all(&test_dir);
        }

        let wallet = Wallet::new(&test_dir)?;
        wallet.set_seed(&[1u8; 64])?;

        // An address that never received comes back every time.
        let first = wallet.get_receive_address()?;
        for _ in 0..10 {
            assert_eq!(wallet.get_receive_address()?, first);
        }
        assert_eq!(wallet.get_addresses()?.len(), 500);

        // A fresh address is still fresh, so a change output never reuses one.
        let fresh = wallet.get_new_address()?;
        assert_ne!(fresh, first);
        assert_eq!(wallet.get_addresses()?.len(), 501);

        // The receive address moves on once it receives.
        let outpoint = OutPoint::Regular {
            txid: [0; 32].into(),
            vout: 0,
        };
        let output = Output {
            address: wallet.get_receive_address()?,
            content: OutputContent::Value(bitcoin::Amount::from_sat(1000)),
        };
        wallet.put_utxos(&HashMap::from([(outpoint, output)]))?;
        let second = wallet.get_receive_address()?;
        assert_ne!(second, first);
        assert_eq!(wallet.get_receive_address()?, second);

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    #[test]
    fn test_new_address_follows_legacy_range() -> anyhow::Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("thunder_test_index0_{nanos}"));
        if test_dir.exists() {
            let _unused = std::fs::remove_dir_all(&test_dir);
        }

        let wallet = Wallet::new(&test_dir)?;
        wallet.set_seed(&[1u8; 64])?;
        assert_eq!(wallet.get_num_addresses()?, 500);

        for index in 500..503u32 {
            let address = wallet.get_new_address()?;
            let txn = wallet.env.read_txn()?;
            let expected = get_address(
                &wallet.get_signing_key(&txn, index)?.verifying_key(),
            );
            drop(txn);
            assert_eq!(
                address, expected,
                "address {index} derives at index {index}"
            );
            assert_eq!(wallet.get_num_addresses()?, index + 1);
        }

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    #[test]
    fn test_get_or_generate_last_address() -> anyhow::Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("thunder_test_wallet_{nanos}"));

        // Ensure clean state
        if test_dir.exists() {
            let _unused = std::fs::remove_dir_all(&test_dir);
        }

        let wallet = Wallet::new(&test_dir)?;

        assert!(!wallet.has_seed()?);
        assert!(wallet.try_get_last_address()?.is_none());
        let seed = [1u8; 64];
        wallet.set_seed(&seed)?;
        assert!(wallet.has_seed()?);

        let last = wallet.try_get_last_address()?;
        let addr1 = wallet.get_or_generate_last_address()?;
        assert_eq!(last, Some(addr1));

        let last = wallet.try_get_last_address()?;
        assert_eq!(last, Some(addr1));

        let addr2 = wallet.get_or_generate_last_address()?;
        assert_eq!(addr1, addr2);

        let addr3 = wallet.get_new_address()?;
        assert_ne!(addr1, addr3);

        let last = wallet.try_get_last_address()?;
        assert_eq!(last, Some(addr3));

        let addr4 = wallet.get_or_generate_last_address()?;
        assert_eq!(addr3, addr4);

        // Clean up
        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    fn funded_wallet(
        name: &str,
        values_sats: &[u64],
    ) -> anyhow::Result<(std::path::PathBuf, Wallet, Accumulator)> {
        use crate::types::AccumulatorDiff;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("thunder_test_{name}_{nanos}"));
        if test_dir.exists() {
            let _unused = std::fs::remove_dir_all(&test_dir);
        }
        let wallet = Wallet::new(&test_dir)?;
        wallet.set_seed(&[2u8; 64])?;

        let mut utxos = HashMap::new();
        let mut diff = AccumulatorDiff::default();
        for (index, value_sats) in values_sats.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid: [index as u8; 32].into(),
                vout: 0,
            };
            let output = Output {
                address: wallet.get_new_address()?,
                content: OutputContent::Value(bitcoin::Amount::from_sat(
                    *value_sats,
                )),
            };
            let pointed = PointedOutput {
                outpoint,
                output: output.clone(),
            };
            diff.insert((&pointed).into());
            utxos.insert(outpoint, output);
        }
        wallet.put_utxos(&utxos)?;
        let mut accumulator = Accumulator::default();
        accumulator.apply_diff(diff)?;
        Ok((test_dir, wallet, accumulator))
    }

    fn value_of(output: &Output) -> u64 {
        output.get_value().to_sat()
    }

    #[test]
    fn test_create_transaction_many_pays_each_address() -> anyhow::Result<()> {
        let (test_dir, wallet, accumulator) =
            funded_wallet("transfer_many", &[10_000])?;

        let dests = BTreeMap::from([
            (Address([1u8; 20]), bitcoin::Amount::from_sat(1000)),
            (Address([2u8; 20]), bitcoin::Amount::from_sat(2000)),
            (Address([3u8; 20]), bitcoin::Amount::from_sat(3000)),
        ]);
        let fee = bitcoin::Amount::from_sat(500);
        let tx = wallet.create_transaction_many(&accumulator, &dests, fee)?;

        assert_eq!(tx.outputs.len(), 4);
        for (index, (address, value)) in dests.iter().enumerate() {
            assert_eq!(tx.outputs[index].address, *address);
            assert_eq!(value_of(&tx.outputs[index]), value.to_sat());
        }
        let change = &tx.outputs[3];
        assert_eq!(value_of(change), 10_000 - 1000 - 2000 - 3000 - 500);
        assert!(wallet.get_addresses()?.contains(&change.address));

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    #[test]
    fn test_create_transaction_keeps_one_payment_and_change()
    -> anyhow::Result<()> {
        let (test_dir, wallet, accumulator) =
            funded_wallet("transfer_one", &[10_000])?;

        let dest = Address([4u8; 20]);
        let tx = wallet.create_transaction(
            &accumulator,
            dest,
            bitcoin::Amount::from_sat(1000),
            bitcoin::Amount::from_sat(500),
        )?;

        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].address, dest);
        assert_eq!(value_of(&tx.outputs[0]), 1000);
        assert_eq!(value_of(&tx.outputs[1]), 10_000 - 1000 - 500);
        assert!(wallet.get_addresses()?.contains(&tx.outputs[1].address));

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    #[test]
    fn test_create_transaction_many_rejects_an_overflow() -> anyhow::Result<()>
    {
        let (test_dir, wallet, accumulator) =
            funded_wallet("transfer_overflow", &[10_000])?;

        let half = bitcoin::Amount::from_sat(bitcoin::Amount::MAX.to_sat() / 2);
        let dests = BTreeMap::from([
            (Address([1u8; 20]), half),
            (Address([2u8; 20]), half + bitcoin::Amount::from_sat(1)),
        ]);
        let result = wallet.create_transaction_many(
            &accumulator,
            &dests,
            bitcoin::Amount::from_sat(500),
        );
        assert!(matches!(result, Err(Error::AmountOverflow(_))));

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    #[test]
    fn test_create_transaction_many_needs_a_destination() -> anyhow::Result<()>
    {
        let (test_dir, wallet, accumulator) =
            funded_wallet("transfer_none", &[10_000])?;

        let result = wallet.create_transaction_many(
            &accumulator,
            &BTreeMap::new(),
            bitcoin::Amount::from_sat(500),
        );
        assert!(matches!(result, Err(Error::NoTransferDestination)));

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }

    #[test]
    fn test_create_transaction_many_totals_the_values() -> anyhow::Result<()> {
        let (test_dir, wallet, accumulator) =
            funded_wallet("transfer_total", &[1000, 1000])?;

        let dests = BTreeMap::from([
            (Address([1u8; 20]), bitcoin::Amount::from_sat(900)),
            (Address([2u8; 20]), bitcoin::Amount::from_sat(900)),
        ]);
        // Each coin alone is too small, so the sum decides the selection.
        let tx = wallet.create_transaction_many(
            &accumulator,
            &dests,
            bitcoin::Amount::from_sat(100),
        )?;
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(value_of(&tx.outputs[2]), 100);

        let result = wallet.create_transaction_many(
            &accumulator,
            &dests,
            bitcoin::Amount::from_sat(1000),
        );
        assert!(matches!(result, Err(Error::NotEnoughFunds)));

        let _unused = std::fs::remove_dir_all(&test_dir);
        Ok(())
    }
}
