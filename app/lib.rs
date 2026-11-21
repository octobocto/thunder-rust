//! Thunder node and RPC server, as a library

use std::net::SocketAddr;

use tokio_util::sync::CancellationToken;

pub mod app;
pub mod cli;
pub mod rpc_server;

#[derive(Debug)]
pub struct Config {
    pub app: app::Config,
    pub private_rpc_addr: SocketAddr,
    pub rpc_addr: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("app error")]
    App(#[from] app::Error),
    #[error("Failed to build the tokio runtime")]
    BuildRuntime(#[source] std::io::Error),
    #[error("Failed to start the RPC server at `{rpc_addr}`")]
    RpcServer {
        rpc_addr: SocketAddr,
        source: anyhow::Error,
    },
}

/// Run the node and the RPC server until `shutdown` is cancelled, or until
/// the `stop` RPC method is called.
/// Blocks the calling thread, which must not be a tokio runtime thread.
/// Returns after every task of the node stopped, so a later call can open
/// the same data dir.
pub fn run(config: Config, shutdown: CancellationToken) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::BuildRuntime)?;
    let app = match app::App::new(config.app, &runtime, &shutdown) {
        Ok(app) => app,
        Err(app::Error::Cancelled) => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let res = runtime.block_on(async {
        tracing::info!(rpc_addr = %config.rpc_addr, "Starting RPC server");
        let server_handles = rpc_server::run_server(
            app.clone(),
            config.private_rpc_addr,
            config.rpc_addr,
            shutdown.clone(),
        )
        .await
        .map_err(|err| Error::RpcServer {
            rpc_addr: config.rpc_addr,
            source: err,
        })?;
        let () = shutdown.cancelled().await;
        let () = server_handles.stop().await;
        Ok(())
    });
    drop(app);
    // Every task drops with the runtime, and with them every database env.
    drop(runtime);
    res
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashSet, net::Ipv4Addr, thread::JoinHandle, time::Duration,
    };

    use jsonrpsee::{
        core::client::ClientT as _, http_client::HttpClient, rpc_params,
    };
    use thunder::types::Network;
    use thunder_app_rpc_api::node::RpcClient as _;
    use tokio_util::sync::CancellationToken;

    use crate::{Config, Error, app, run};

    /// Returns `false` if `node` returned before the RPC server answered
    async fn wait_for_rpc(
        client: &HttpClient,
        node: &JoinHandle<Result<(), Error>>,
    ) -> anyhow::Result<bool> {
        const RETRY_DELAY: Duration = Duration::from_millis(100);
        const TIMEOUT: Duration = Duration::from_secs(60);
        let answered = tokio::time::timeout(TIMEOUT, async {
            loop {
                if client.getblockcount().await.is_ok() {
                    break true;
                }
                if node.is_finished() {
                    break false;
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
        })
        .await?;
        Ok(answered)
    }

    /// Every database env must close when `run` returns, because heed does
    /// not open the same env path two times in one process.
    #[test]
    fn run_again_in_the_same_process() -> anyhow::Result<()> {
        let temp_dir = temp_dir::TempDir::new()?;
        let validator_addr =
            reserve_port::ReservedSocketAddr::reserve_random_socket_addr()?
                .socket_addr();
        let rpc_addr =
            reserve_port::ReservedSocketAddr::reserve_random_socket_addr()?
                .socket_addr();
        let test_runtime = tokio::runtime::Runtime::new()?;
        let () = test_runtime
            .block_on(app::test::serve_validator_service(validator_addr));
        let client = {
            let _rt_guard = test_runtime.enter();
            HttpClient::builder().build(format!("http://{rpc_addr}"))?
        };
        for stop_with_rpc in [false, true] {
            let config = Config {
                app: app::Config {
                    add_peers: HashSet::new(),
                    datadir: temp_dir.path().join("data"),
                    mainchain_grpc_url: format!("http://{validator_addr}")
                        .parse()?,
                    mnemonic_seed_phrase_path: None,
                    net_addr: (Ipv4Addr::LOCALHOST, 0).into(),
                    network: Network::Regtest,
                    network_magic_override: None,
                    server_names: HashSet::new(),
                    wallet_dir: temp_dir.path().join("wallet"),
                },
                private_rpc_addr: rpc_addr,
                rpc_addr,
            };
            let shutdown = CancellationToken::new();
            let node = std::thread::spawn({
                let shutdown = shutdown.clone();
                move || run(config, shutdown)
            });
            let answered = test_runtime.block_on(async {
                if !wait_for_rpc(&client, &node).await? {
                    return anyhow::Ok(false);
                }
                if stop_with_rpc {
                    // `PrivateRpcClient::stop` sends a notification, which
                    // the server does not run.
                    let response: serde_json::Value =
                        client.request("stop", rpc_params![]).await?;
                    assert!(response.is_null());
                } else {
                    shutdown.cancel();
                }
                anyhow::Ok(true)
            })?;
            let () = node
                .join()
                .map_err(|_| anyhow::anyhow!("the node thread panicked"))??;
            anyhow::ensure!(answered, "run returned before the RPC answered");
        }
        Ok(())
    }
}
