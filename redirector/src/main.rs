mod adapter;
mod divert;
mod flows;
mod observer;
mod pidlookup;
mod policy;
// The unauthenticated policy pipe is intentionally not exposed by production.
mod proc_watcher;
mod process;
mod shutdown;
mod stack;
mod status_server;
mod tunneled;
mod vpn_state;

use std::sync::Arc;

use anyhow::Result;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        None | Some("adapters") => print_adapters(),
        Some("observe") => {
            let shutdown_event = match args.get(2).map(String::as_str) {
                None => None,
                Some("--shutdown-event") if args.len() == 4 => Some(args[3].as_str()),
                _ => anyhow::bail!("usage: redirector observe [--shutdown-event NAME]"),
            };
            run_observe(shutdown_event)
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(cmd) => {
            eprintln!("unknown command: {}", cmd);
            print_help();
            std::process::exit(2);
        }
    }
}

fn run_observe(shutdown_event: Option<&str>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        use anyhow::Context;
        let shutdown = shutdown::Shutdown::new();
        let external_stop = shutdown::ExternalStop::open(shutdown_event)?;
        let policy_state = policy::new();
        let flows = flows::new();
        let resolver = Arc::new(process::Resolver::new());
        let tunneled_paths = tunneled::new();
        // Do not start capture against a transiently empty policy.
        tunneled::replace(
            &tunneled_paths,
            tunneled::load_initial().context("load initial tunnel configuration")?,
        );

        let vpn_state = vpn_state::new();
        let bus = Arc::new(status_server::StatusBus::new());

        let mut services = tokio::task::JoinSet::new();
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(vpn_state::watcher(
            vpn_state.clone(),
            bus.clone(),
            shutdown.clone(),
        ));
        services.spawn(status_server::run(bus.clone(), vpn_state.clone()));
        services.spawn(proc_watcher::run(
            policy_state.clone(),
            bus.clone(),
            tunneled_paths.clone(),
        ));
        {
            let resolver = resolver.clone();
            let policy_state = policy_state.clone();
            let flows = flows.clone();
            let shutdown = shutdown.clone();
            workers.spawn_blocking(move || observer::run(resolver, policy_state, flows, shutdown));
        };
        {
            let policy_state = policy_state.clone();
            let flows = flows.clone();
            let vpn_state = vpn_state.clone();
            let bus = bus.clone();
            let resolver = resolver.clone();
            let tunneled_paths = tunneled_paths.clone();
            let shutdown = shutdown.clone();
            workers.spawn_blocking(move || {
                divert::run(
                    policy_state,
                    flows,
                    vpn_state,
                    bus,
                    resolver,
                    tunneled_paths,
                    shutdown,
                )
            });
        };

        let stop = async {
            tokio::select! {
                r = tokio::signal::ctrl_c() => r.context("console shutdown signal"),
                r = external_stop.wait() => r,
            }
        };
        supervise(services, workers, shutdown, stop).await
    });
    // A broken native API must not make Runtime::drop wait forever.
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    result
}

async fn supervise(
    mut services: tokio::task::JoinSet<Result<()>>,
    mut workers: tokio::task::JoinSet<Result<()>>,
    shutdown: shutdown::Shutdown,
    stop: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    use anyhow::Context;
    let result = tokio::select! {
        r = services.join_next() => task_result(r),
        r = workers.join_next() => task_result(r),
        r = stop => r,
    };
    shutdown.stop();
    services.abort_all();
    let cleanup = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while services.join_next().await.is_some() {}
        let mut first_error = None;
        while let Some(r) = workers.join_next().await {
            if let Err(error) = r.context("worker join failed").and_then(|r| r) {
                tracing::error!(%error, "worker stopped with an error");
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    })
    .await
    .context("backend shutdown timed out")
    .and_then(|r| r);
    result.and(cleanup)
}

fn task_result(
    result: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
) -> Result<()> {
    use anyhow::Context;
    result
        .context("worker set unexpectedly empty")?
        .context("backend worker panicked")??;
    anyhow::bail!("backend worker exited unexpectedly")
}

fn print_help() {
    println!("redirector — VPN per-app routing service");
    println!();
    println!("USAGE:");
    println!("  redirector [adapters]    List network adapters, flag VPN candidates");
    println!("  redirector observe       Run per-app routing + status pipe (requires admin)");
    println!("  redirector help          Show this message");
}

fn print_adapters() -> Result<()> {
    let adapters = adapter::enumerate()?;
    println!("Found {} adapters\n", adapters.len());

    for a in &adapters {
        let status = if a.is_up { "UP  " } else { "DOWN" };
        let marker = if a.is_vpn_candidate() {
            "  <-- VPN candidate"
        } else {
            ""
        };
        println!("[{}] {}{}", status, a.friendly_name, marker);
        println!("       description: {}", a.description);
        println!("       guid:        {}", a.adapter_name);
        if a.addresses.is_empty() {
            println!("       (no addresses)");
        } else {
            for ip in &a.addresses {
                println!("       address:     {}", ip);
            }
        }
        println!();
    }

    let vpn: Vec<_> = adapters
        .iter()
        .filter(|a| a.is_vpn_candidate() && a.is_up)
        .collect();
    match vpn.as_slice() {
        [] => println!("No active VPN adapter detected. Start OpenVPN before continuing."),
        [one] => println!(
            "VPN adapter ready: {} ({} addresses)",
            one.friendly_name,
            one.addresses.len()
        ),
        many => println!(
            "Multiple VPN adapter candidates ({}) — narrow your config",
            many.len()
        ),
    }
    Ok(())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_failure_stops_and_joins_blocking_capture() {
        let shutdown = shutdown::Shutdown::new();
        let mut services = tokio::task::JoinSet::new();
        let mut workers = tokio::task::JoinSet::new();
        let released = Arc::new(AtomicBool::new(false));
        let released_by_worker = released.clone();
        let worker_stop = shutdown.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        workers.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            while !worker_stop.is_stopped() {
                std::thread::sleep(Duration::from_millis(10));
            }
            released_by_worker.store(true, Ordering::Release);
            Ok(())
        });
        services.spawn(async move {
            started_rx.await.unwrap();
            anyhow::bail!("simulated IPC failure")
        });
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            supervise(services, workers, shutdown, std::future::pending()),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("simulated IPC failure"));
        assert!(released.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn requested_stop_waits_for_cleanup() {
        let shutdown = shutdown::Shutdown::new();
        let mut services = tokio::task::JoinSet::new();
        let mut workers = tokio::task::JoinSet::new();
        services.spawn(std::future::pending());
        let worker_stop = shutdown.clone();
        let released = Arc::new(AtomicBool::new(false));
        let released_by_worker = released.clone();
        workers.spawn(async move {
            while !worker_stop.is_stopped() {
                tokio::task::yield_now().await;
            }
            released_by_worker.store(true, Ordering::Release);
            Ok(())
        });
        supervise(services, workers, shutdown, async { Ok(()) })
            .await
            .unwrap();
        assert!(released.load(Ordering::Acquire));
    }
}
