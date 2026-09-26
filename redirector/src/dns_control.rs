//! Private per-backend opt-in handshake. Loss of control input never silently
//! disables interception while the independent guard may still own Dnscache.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;
use serde_json::Value;

use crate::process::{ProcessInfo, Resolver};
use crate::session_binding::DnsSession;

const MAX_BYTES: u64 = 4096;
type ControlResult<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub pid: u32,
    pub creation_time: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Acknowledgement {
    pub armed: bool,
    pub lease: Option<[u8; 16]>,
    pub revision: u64,
    pub error: &'static str,
    pub session: Option<[u8; 16]>,
    pub generation: Option<[u8; 16]>,
}

impl Acknowledgement {
    pub fn permits(&self, dns: &DnsSession) -> bool {
        self.armed
            && self.session == Some(dns.target.session_id)
            && self.generation == Some(dns.generation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Command {
    revision: u64,
    lease: [u8; 16],
    armed: bool,
    owner: Identity,
    backend: Identity,
    session: [u8; 16],
    generation: [u8; 16],
}

impl Command {
    fn parse(bytes: &[u8]) -> ControlResult<Self> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| "control_invalid")?;
        let fields = value.as_object().ok_or("control_invalid")?;
        let number = |name: &str| {
            fields
                .get(name)
                .and_then(Value::as_u64)
                .ok_or("control_invalid")
        };
        let guid = |name: &str| {
            let value = fields
                .get(name)
                .and_then(Value::as_str)
                .ok_or("control_invalid")?;
            if value.len() != 36 {
                return Err("control_invalid");
            }
            crate::session_binding::guid(value).map_err(|_| "control_invalid")
        };
        let pid = |name: &str| {
            let pid = u32::try_from(number(name)?).map_err(|_| "control_invalid")?;
            (pid > 4).then_some(pid).ok_or("control_invalid")
        };
        if number("version")? != 1 || fields.len() != 10 {
            return Err("control_invalid");
        }
        let result = Self {
            revision: number("revision")?,
            lease: guid("lease")?,
            armed: fields
                .get("armed")
                .and_then(Value::as_bool)
                .ok_or("control_invalid")?,
            owner: Identity {
                pid: pid("ownerPid")?,
                creation_time: number("ownerCreationTime")?,
            },
            backend: Identity {
                pid: pid("backendPid")?,
                creation_time: number("backendCreationTime")?,
            },
            session: guid("sessionId")?,
            generation: guid("generation")?,
        };
        if result.revision == 0
            || result.owner.creation_time == 0
            || result.backend.creation_time == 0
        {
            return Err("control_invalid");
        }
        Ok(result)
    }
}

#[derive(Default)]
struct State {
    acknowledgement: Acknowledgement,
    owner: Option<Identity>,
    last: Option<Command>,
}

impl State {
    fn apply(
        &mut self,
        command: Command,
        backend: Identity,
        dns: Option<&DnsSession>,
        resolve: impl FnOnce(u32) -> Option<ProcessInfo>,
        cleanup: impl FnOnce(),
    ) -> ControlResult<()> {
        if command.backend != backend {
            return Err("control_backend_mismatch");
        }
        if command.revision < self.acknowledgement.revision {
            return Err("control_stale_revision");
        }
        if command.revision == self.acknowledgement.revision {
            return if self.last == Some(command) {
                Ok(())
            } else {
                Err("control_revision_conflict")
            };
        }
        if self.owner.is_some_and(|owner| owner != command.owner) {
            return Err("control_owner_mismatch");
        }
        if self.acknowledgement.armed && self.acknowledgement.lease != Some(command.lease) {
            return Err("control_lease_mismatch");
        }
        if command.armed || self.owner.is_none() {
            let owner = resolve(command.owner.pid).ok_or("control_owner_unavailable")?;
            if owner.creation_time != command.owner.creation_time {
                return Err("control_owner_mismatch");
            }
        }
        if command.armed {
            let dns = dns.ok_or("control_session_unavailable")?;
            if dns.target.session_id != command.session || dns.generation != command.generation {
                return Err("control_session_mismatch");
            }
        }
        // Includes worker cancellation, smoltcp sockets and queued DNS packets.
        // Publish the new state only after the capture loop applied this barrier.
        cleanup();
        self.owner = Some(command.owner);
        self.last = Some(command);
        self.acknowledgement = Acknowledgement {
            armed: command.armed,
            lease: Some(command.lease),
            revision: command.revision,
            error: "",
            session: Some(command.session),
            generation: Some(command.generation),
        };
        Ok(())
    }
}

pub struct ControlSource {
    path: PathBuf,
    backend: Identity,
    state: Mutex<State>,
}

impl ControlSource {
    pub fn new(path: &Path, resolver: &Resolver) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute(),
            "--dns-control-file must be an absolute private path"
        );
        let pid = std::process::id();
        let process = resolver
            .resolve(pid)
            .ok_or_else(|| anyhow::anyhow!("read backend identity for DNS control"))?;
        Ok(Self {
            path: path.to_owned(),
            backend: Identity {
                pid,
                creation_time: process.creation_time,
            },
            state: Mutex::new(State::default()),
        })
    }

    pub fn current(&self) -> Acknowledgement {
        self.state.lock().unwrap().acknowledgement
    }

    pub fn poll(
        &self,
        dns: Option<&DnsSession>,
        resolver: &Resolver,
        cleanup: impl FnOnce(),
    ) -> Acknowledgement {
        let input = read_command(&self.path);
        let mut state = self.state.lock().unwrap();
        let previous_error = state.acknowledgement.error;
        let result = match input {
            Ok(Some(command)) => state.apply(
                command,
                self.backend,
                dns,
                |pid| resolver.resolve(pid),
                cleanup,
            ),
            Ok(None) if state.acknowledgement.revision == 0 => Ok(()),
            Ok(None) => Err("control_missing"),
            Err(error) => Err(error),
        };
        state.acknowledgement.error = result.err().unwrap_or("");
        if !state.acknowledgement.error.is_empty()
            && state.acknowledgement.error != previous_error
            && crate::dns_broker::trace::allow(crate::dns_broker::trace::Category::Failure)
        {
            tracing::warn!(
                code = state.acknowledgement.error,
                armed = state.acknowledgement.armed,
                revision = state.acknowledgement.revision,
                "DNS control input rejected; applied state retained"
            );
        }
        state.acknowledgement
    }
}

fn read_command(path: &Path) -> ControlResult<Option<Command>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("control_read_failed"),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "control_read_failed")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("control_too_large");
    }
    Command::parse(&bytes).map(Some)
}

#[cfg(test)]
mod tests;
