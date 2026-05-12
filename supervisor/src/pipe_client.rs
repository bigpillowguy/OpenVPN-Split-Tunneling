use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use ipc::PolicyMessage;

pub struct PipeClient {
    file: Mutex<File>,
}

impl PipeClient {
    pub fn connect(path: &str) -> Result<Self> {
        for attempt in 0..20 {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(f) => {
                    return Ok(Self {
                        file: Mutex::new(f),
                    });
                }
                Err(e) if attempt < 19 => {
                    tracing::debug!("pipe open attempt {}: {}", attempt + 1, e);
                    std::thread::sleep(Duration::from_millis(150));
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("opening policy pipe {}", path));
                }
            }
        }
        unreachable!()
    }

    pub fn send(&self, msg: &PolicyMessage) -> Result<()> {
        let mut buf = Vec::with_capacity(64);
        ipc::encode_frame(msg, &mut buf);
        let mut file = self.file.lock().unwrap();
        file.write_all(&buf).context("writing to policy pipe")?;
        file.flush().context("flushing policy pipe")?;
        Ok(())
    }
}
