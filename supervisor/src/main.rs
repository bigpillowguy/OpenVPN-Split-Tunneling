mod job;
mod launcher;
mod pipe_client;

use anyhow::Result;

use job::JobEvent;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("launch") if args.len() >= 3 => {
            let exe = args[2].clone();
            let rest: Vec<String> = args[3..].to_vec();
            run_launch(exe, rest)
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        _ => {
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("supervisor — launch apps under VPN tunneling policy");
    println!();
    println!("USAGE:");
    println!("  supervisor launch <exe> [args...]    Launch app inside a Job Object,");
    println!("                                       publish PID tree to the policy pipe");
    println!("  supervisor help                      Show this message");
}

fn run_launch(exe: String, args: Vec<String>) -> Result<()> {
    tracing::info!("connecting to policy pipe {}", ipc::PIPE_NAME);
    let pipe = pipe_client::PipeClient::connect(ipc::PIPE_NAME)?;
    tracing::info!("connected");

    let job = job::Job::create()?;
    let events = job.start_event_loop()?;

    let proc = launcher::spawn_suspended(&job, &exe, &args)?;
    tracing::info!("created {} as PID {} (suspended)", exe, proc.pid);
    pipe.send(&ipc::add_pid(proc.pid))?;
    // Give the redirector a moment to process the AddPid before the process can
    // touch the network. Without this, fast-launching apps like curl race past
    // the policy update and their first connection escapes to the default route.
    std::thread::sleep(std::time::Duration::from_millis(60));
    let pid = proc.pid;
    launcher::resume(proc)?;
    tracing::info!("resumed PID {}", pid);

    for event in events {
        match event {
            JobEvent::NewProcess(pid) => {
                tracing::info!("+ pid {}", pid);
                if let Err(e) = pipe.send(&ipc::add_pid(pid)) {
                    tracing::warn!("send add_pid({}) failed: {}", pid, e);
                }
            }
            JobEvent::ExitProcess(pid) => {
                tracing::info!("- pid {}", pid);
                if let Err(e) = pipe.send(&ipc::remove_pid(pid)) {
                    tracing::warn!("send remove_pid({}) failed: {}", pid, e);
                }
            }
            JobEvent::ActiveZero => {
                tracing::info!("all processes in job exited");
                break;
            }
        }
    }

    Ok(())
}
