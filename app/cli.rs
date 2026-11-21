use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::LazyLock,
};

use clap::{Arg, Parser};
use thunder::types::{Network, THIS_SIDECHAIN};

#[derive(Clone, Debug)]
pub struct Config {
    pub add_peers: HashSet<thunder::types::net::PeerAddress>,
    pub datadir: PathBuf,
    pub headless: bool,
    /// If None, logging to file should be disabled.
    pub log_dir: Option<PathBuf>,
    pub log_level: tracing::Level,
    pub log_level_file: tracing::Level, // Level for logs that get written to file
    pub mainchain_grpc_url: url::Url,
    pub mnemonic_seed_phrase_path: Option<PathBuf>,
    pub net_addr: SocketAddr,
    pub network: Network,
    pub network_magic_override: Option<thunder::net::peer_message::MagicBytes>,
    pub private_rpc_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
    pub server_names: HashSet<String>,
    pub wallet_dir: PathBuf,
}

impl Config {
    /// Log all fields at info level
    #[track_caller]
    pub fn log_all_fields(&self, msg: &str) {
        let Self {
            add_peers,
            datadir,
            headless,
            log_dir,
            log_level,
            log_level_file,
            mainchain_grpc_url,
            mnemonic_seed_phrase_path,
            net_addr,
            network,
            network_magic_override,
            private_rpc_addr,
            rpc_addr,
            server_names,
            wallet_dir,
        } = self;
        let add_peers = std::fmt::from_fn(|f| {
            f.debug_set()
                .entries(add_peers.iter().map(|peer_addr| {
                    std::fmt::from_fn(|f| std::fmt::Display::fmt(peer_addr, f))
                }))
                .finish()
        });
        tracing::info!(
            %add_peers,
            datadir = %datadir.display(),
            %headless,
            log_dir = log_dir.as_ref().map(|path|
                tracing::field::display(path.display())
            ),
            %log_level,
            %log_level_file,
            %mainchain_grpc_url,
            mnemonic_seed_phrase_path = mnemonic_seed_phrase_path.as_ref()
                .map(|path| tracing::field::display(path.display())),
            %net_addr,
            %network,
            network_magic_override = network_magic_override.map(|magic|
                tracing::field::display(const_hex::encode(magic))
            ),
            %private_rpc_addr,
            %rpc_addr,
            ?server_names,
            wallet_dir = %wallet_dir.display(),
            msg,
        )
    }

    /// The config that [`crate::run`] takes
    pub fn run_config(&self) -> crate::Config {
        crate::Config {
            app: crate::app::Config {
                add_peers: self.add_peers.clone(),
                datadir: self.datadir.clone(),
                mainchain_grpc_url: self.mainchain_grpc_url.clone(),
                mnemonic_seed_phrase_path: self
                    .mnemonic_seed_phrase_path
                    .clone(),
                net_addr: self.net_addr,
                network: self.network,
                network_magic_override: self.network_magic_override,
                server_names: self.server_names.clone(),
                wallet_dir: self.wallet_dir.clone(),
            },
            private_rpc_addr: self.private_rpc_addr,
            rpc_addr: self.rpc_addr,
        }
    }
}

/// Saturating predecessor of a log level
pub fn saturating_pred_level(log_level: tracing::Level) -> tracing::Level {
    match log_level {
        tracing::Level::TRACE => tracing::Level::DEBUG,
        tracing::Level::DEBUG => tracing::Level::INFO,
        tracing::Level::INFO => tracing::Level::WARN,
        tracing::Level::WARN => tracing::Level::ERROR,
        tracing::Level::ERROR => tracing::Level::ERROR,
    }
}

const fn ipv4_socket_addr(ipv4_octets: [u8; 4], port: u16) -> SocketAddr {
    let [a, b, c, d] = ipv4_octets;
    let ipv4 = Ipv4Addr::new(a, b, c, d);
    SocketAddr::new(IpAddr::V4(ipv4), port)
}

static DEFAULT_DATA_DIR: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| match dirs::data_dir() {
        None => {
            tracing::warn!("Failed to resolve default data dir");
            None
        }
        Some(data_dir) => Some(data_dir.join("thunder")),
    });

const DEFAULT_NET_ADDR: SocketAddr =
    ipv4_socket_addr([0, 0, 0, 0], 4000 + THIS_SIDECHAIN as u16);

const DEFAULT_RPC_ADDR: SocketAddr =
    ipv4_socket_addr([127, 0, 0, 1], 6000 + THIS_SIDECHAIN as u16);

/// Implement arg manually so that there is only a default if we can resolve
/// the default data dir
#[derive(Clone, Debug)]
#[repr(transparent)]
struct DatadirArg(PathBuf);

impl clap::FromArgMatches for DatadirArg {
    fn from_arg_matches(
        matches: &clap::ArgMatches,
    ) -> Result<Self, clap::Error> {
        let mut matches = matches.clone();
        Self::from_arg_matches_mut(&mut matches)
    }

    fn from_arg_matches_mut(
        matches: &mut clap::ArgMatches,
    ) -> Result<Self, clap::Error> {
        let datadir = matches
            .remove_one::<PathBuf>("DATADIR")
            .expect("`datadir` is required");
        Ok(Self(datadir))
    }

    fn update_from_arg_matches(
        &mut self,
        matches: &clap::ArgMatches,
    ) -> Result<(), clap::Error> {
        let mut matches = matches.clone();
        self.update_from_arg_matches_mut(&mut matches)
    }

    fn update_from_arg_matches_mut(
        &mut self,
        matches: &mut clap::ArgMatches,
    ) -> Result<(), clap::Error> {
        if let Some(datadir) = matches.remove_one("DATADIR") {
            self.0 = datadir;
        }
        Ok(())
    }
}

impl clap::Args for DatadirArg {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd.arg({
            let arg = Arg::new("DATADIR")
                .value_parser(clap::builder::PathBufValueParser::new())
                .long("datadir")
                .short('d')
                .help("Data directory for storing blockchain and wallet data");
            match DEFAULT_DATA_DIR.deref() {
                None => arg.required(true),
                Some(datadir) => {
                    arg.required(false).default_value(datadir.as_os_str())
                }
            }
        })
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

#[inline(always)]
fn parse_network_magic(s: &str) -> Result<[u8; 4], const_hex::FromHexError> {
    const_hex::decode_to_array(s)
}

#[derive(Clone, Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Additional peers to dial on startup, as `host:port`. May be given
    /// more than once, and is dialed in addition to the network's built-in
    /// seed peers.
    #[arg(long = "add-peer")]
    add_peers: Vec<thunder::types::net::PeerAddress>,
    /// Data directory for storing blockchain data.
    /// Wallet data is stored here by default.
    #[command(flatten)]
    datadir: DatadirArg,
    /// If specified, the gui will not launch.
    #[arg(long)]
    headless: bool,
    /// Directory in which to store log files.
    /// Defaults to `<DATADIR>/logs/v<VERSION>`, where `<DATADIR>` is thunder's data
    /// directory, and `<VERSION>` is the thunder app version.
    /// By default, only logs at the WARN level and above are logged to file.
    /// If set to the empty string, logging to file will be disabled.
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Log level for logs that get written to file
    #[arg(default_value_t = tracing::Level::WARN, long)]
    log_level_file: tracing::Level,

    /// Log level
    #[arg(default_value_t = tracing::Level::DEBUG, long)]
    log_level: tracing::Level,

    /// Connect to mainchain node gRPC server running at this URL
    #[arg(default_value = "http://localhost:50051", long)]
    mainchain_grpc_url: url::Url,

    /// Path to a mnemonic seed phrase
    #[arg(long)]
    mnemonic_seed_phrase_path: Option<PathBuf>,
    /// Socket address to use for P2P networking
    #[arg(default_value_t = DEFAULT_NET_ADDR, long, short)]
    net_addr: SocketAddr,
    /// Set the network. Setting this may affect other defaults.
    #[arg(default_value_t, long, value_enum)]
    network: Network,
    /// Manually provide the network magic bytes
    #[arg(long, value_parser = parse_network_magic)]
    network_magic: Option<[u8; 4]>,
    /// Socket address to host the private RPC server
    #[arg(default_value_t = DEFAULT_RPC_ADDR, long, short)]
    private_rpc_addr: SocketAddr,
    /// Socket address to host the RPC server
    #[arg(default_value_t = DEFAULT_RPC_ADDR, long, short)]
    rpc_addr: SocketAddr,
    /// Host name used by the p2p server.
    /// This option can be specified multiple times.
    #[arg(long = "server-name")]
    server_names: Vec<String>,
    /// Data directory for storing wallet data
    #[arg(long)]
    wallet_dir: Option<PathBuf>,
}

impl Cli {
    /// Parse the command line flags. `args` starts with the program name.
    pub fn try_parse_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::try_parse_from(args)
    }

    pub fn get_config(self) -> anyhow::Result<Config> {
        let datadir = self.datadir.0;
        let log_dir = match self.log_dir {
            None => {
                let version_dir_name =
                    format!("v{}", env!("CARGO_PKG_VERSION"));
                let log_dir = datadir.join("logs").join(version_dir_name);
                Some(log_dir)
            }
            Some(log_dir) => {
                if log_dir.as_os_str().is_empty() {
                    None
                } else {
                    Some(log_dir)
                }
            }
        };
        let log_level = if self.headless {
            self.log_level
        } else {
            saturating_pred_level(self.log_level)
        };
        let wallet_dir = self.wallet_dir.unwrap_or_else(|| datadir.clone());
        Ok(Config {
            add_peers: HashSet::from_iter(self.add_peers),
            datadir,
            headless: self.headless,
            log_dir,
            log_level,
            log_level_file: self.log_level_file,
            mainchain_grpc_url: self.mainchain_grpc_url,
            mnemonic_seed_phrase_path: self.mnemonic_seed_phrase_path,
            net_addr: self.net_addr,
            network: self.network,
            network_magic_override: self.network_magic,
            private_rpc_addr: self.private_rpc_addr,
            rpc_addr: self.rpc_addr,
            server_names: HashSet::from_iter(self.server_names),
            wallet_dir,
        })
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use thunder::types::Network;

    use super::Cli;

    #[test]
    fn run_config_takes_the_flags() -> anyhow::Result<()> {
        let config = Cli::try_parse_args([
            "thunder_app",
            "--headless",
            "--datadir=/data/thunder",
            "--network=regtest",
            "--rpc-addr=127.0.0.1:16009",
            "--mainchain-grpc-url=http://127.0.0.1:25550",
            "--mnemonic-seed-phrase-path=/data/starter.txt",
        ])?
        .get_config()?;
        let run_config = config.run_config();
        assert_eq!(run_config.app.datadir, PathBuf::from("/data/thunder"));
        assert_eq!(run_config.app.wallet_dir, PathBuf::from("/data/thunder"));
        assert_eq!(run_config.app.network, Network::Regtest);
        assert_eq!(run_config.rpc_addr, "127.0.0.1:16009".parse()?);
        assert_eq!(
            run_config.app.mainchain_grpc_url.as_str(),
            "http://127.0.0.1:25550/"
        );
        assert_eq!(
            run_config.app.mnemonic_seed_phrase_path,
            Some(PathBuf::from("/data/starter.txt"))
        );
        Ok(())
    }

    #[test]
    fn try_parse_args_returns_an_unknown_flag() {
        assert!(
            Cli::try_parse_args(["thunder_app", "--no-such-flag"]).is_err()
        );
    }
}
