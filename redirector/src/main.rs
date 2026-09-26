mod adapter;
mod diagnostics;
mod divert;
mod dns_broker;
mod flows;
mod observer;
mod pidlookup;
mod policy;
// The unauthenticated policy pipe is intentionally not exposed by production.
mod proc_watcher;
mod process;
mod session_binding;
mod shutdown;
mod split_dns;
mod stack;
mod status_server;
mod tunneled;
mod vpn_state;

use std::sync::Arc;

use anyhow::Result;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // Initialize the supplied diagnostic path before validating the remaining
    // arguments, so even startup/usage failures survive a CREATE_NO_WINDOW launch.
    let log_path = args
        .windows(2)
        .find_map(|pair| (pair[0] == "--log-file").then(|| std::path::Path::new(&pair[1])));
    let result = diagnostics::init(log_path).and_then(|()| dispatch(&args));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("backend terminated: {error:#}");
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "backend terminated: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<()> {
    match args.get(1).map(|s| s.as_str()) {
        None | Some("adapters") => print_adapters(),
        Some("observe") => run_observe(observe_options(&args[2..])?),
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(cmd) => {
            eprintln!("unknown command: {}", cmd);
            print_help();
            anyhow::bail!("unknown command: {cmd}")
        }
    }
}

struct ObserveOptions<'a> {
    shutdown_event: Option<&'a str>,
    session_file: &'a std::path::Path,
    dns_pipe: Option<&'a str>,
    split_dns: bool,
}

fn observe_options(args: &[String]) -> Result<ObserveOptions<'_>> {
    let mut shutdown_event = None;
    let mut session_file = None;
    let mut seen_log_file = false;
    let mut dns_pipe = None;
    let mut split_dns = false;
    let mut at = 0;
    while at < args.len() {
        if args[at] == "--split-dns" {
            anyhow::ensure!(!split_dns, "duplicate --split-dns");
            split_dns = true;
            at += 1;
            continue;
        }
        let pair = &args[at..(at + 2).min(args.len())];
        match pair {
            [flag, value] if flag == "--dns-pipe" && dns_pipe.is_none() => {
                dns_broker::pipe_path(value)?;
                dns_pipe = Some(value.as_str());
            }
            [flag, value] if flag == "--shutdown-event" && shutdown_event.is_none() => {
                shutdown_event = Some(value.as_str());
            }
            [flag, value] if flag == "--session-file" && session_file.is_none() => {
                session_file = Some(std::path::Path::new(value));
            }
            [flag, value] if flag == "--log-file" && !seen_log_file => {
                anyhow::ensure!(std::path::Path::new(value).is_absolute(), "--log-file must be an absolute path");
                seen_log_file = true;
            }
            _ => anyhow::bail!(
                "usage: redirector observe --session-file PATH [--shutdown-event NAME] [--log-file PATH] [--dns-pipe NAME] [--split-dns]"
            ),
        }
        at += 2;
    }
    Ok(ObserveOptions {
        shutdown_event,
        dns_pipe,
        split_dns,
        session_file: session_file.ok_or_else(|| {
            anyhow::anyhow!("observe requires --session-file from the UI's current OpenVPN session")
        })?,
    })
}

fn run_observe(options: ObserveOptions<'_>) -> Result<()> {
    tracing::info!("backend starting, version={}", env!("CARGO_PKG_VERSION"));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        use anyhow::Context;
        let shutdown = shutdown::Shutdown::new();
        let external_stop = shutdown::ExternalStop::open(options.shutdown_event)?;
        let policy_state = policy::new();
        let flows = flows::new();
        let resolver = Arc::new(process::Resolver::new());
        let session = session_binding::SessionSource::new(options.session_file, resolver.clone())?;
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
            session.clone(),
        ));
        if let Some(name) = options.dns_pipe {
            services.spawn(dns_broker::run(
                name.to_owned(),
                resolver.clone(),
                vpn_state.clone(),
                session.clone(),
                shutdown.clone(),
            ));
        }
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
            let dns = options.split_dns.then(|| {
                Arc::new(split_dns::LiveAuthority::new(
                    resolver.clone(),
                    session.clone(),
                    vpn_state.clone(),
                    shutdown.clone(),
                ))
            });
            workers.spawn_blocking(move || {
                divert::run(
                    policy_state,
                    flows,
                    vpn_state,
                    bus,
                    resolver,
                    tunneled_paths,
                    shutdown,
                    dns,
                )
            });
        };

        let stop = external_stop.wait_for_request();
        supervise(services, workers, shutdown, stop).await
    });
    // A broken native API must not make Runtime::drop wait forever.
    rt.shutdown_timeout(std::time::Duration::from_secs(1));
    if result.is_ok() {
        tracing::info!("backend shutdown completed");
    }
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
    println!("  redirector observe --session-file PATH [--shutdown-event NAME] [--log-file PATH] [--dns-pipe NAME] [--split-dns]");
    println!(
        "                          Run routing for the UI's bound VPN session (requires admin)"
    );
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

    #[test]
    fn observe_requires_session_binding_and_rejects_ambiguous_options() {
        assert!(observe_options(&[]).is_err());
        let args = [
            "--session-file",
            "C:\\private\\session.json",
            "--shutdown-event",
            "Local\\VpnClient-test",
        ]
        .map(str::to_owned);
        let options = observe_options(&args).unwrap();
        assert!(!options.split_dns);
        assert_eq!(options.session_file, std::path::Path::new(&args[1]));
        assert_eq!(options.shutdown_event, Some(args[3].as_str()));
        let duplicate = ["--session-file", "one", "--session-file", "two"].map(str::to_owned);
        assert!(observe_options(&duplicate).is_err());
        assert!(observe_options(&["--session-file".into()]).is_err());
        let logged = [
            "--session-file",
            "C:\\private\\session.json",
            "--log-file",
            "C:\\private\\redirector.log",
        ]
        .map(str::to_owned);
        assert!(observe_options(&logged).is_ok());
        let mut duplicated_log = logged.to_vec();
        duplicated_log.extend(["--log-file".into(), "C:\\private\\another.log".into()]);
        assert!(observe_options(&duplicated_log).is_err());
        let split =
            ["--split-dns", "--session-file", "C:\\private\\session.json"].map(str::to_owned);
        assert!(observe_options(&split).unwrap().split_dns);
        let mut duplicate_split = split.to_vec();
        duplicate_split.push("--split-dns".into());
        assert!(observe_options(&duplicate_split).is_err());
    }

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
