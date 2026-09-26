use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tracing_subscriber::fmt::MakeWriter;

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone)]
struct LogSink(Option<Arc<Mutex<RotatingFile>>>);

pub fn init(path: Option<&Path>) -> Result<()> {
    let sink = match path {
        Some(path) => {
            anyhow::ensure!(path.is_absolute(), "--log-file must be an absolute path");
            LogSink(Some(Arc::new(Mutex::new(
                RotatingFile::open(path, MAX_LOG_BYTES).context("open backend diagnostic log")?,
            ))))
        }
        None => LogSink(None),
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(sink.clone())
        .try_init()
        .map_err(|error| anyhow::anyhow!("initialize diagnostic logger: {error}"))?;

    std::panic::set_hook(Box::new(move |info| {
        // Avoid tracing and blocking locks here: the panicking thread may have
        // been formatting a diagnostic event while it held the log mutex.
        let message = format!(
            "fatal backend panic: {info}\n{}\n",
            std::backtrace::Backtrace::force_capture()
        );
        if let Some(file) = &sink.0 {
            if let Ok(mut file) = file.try_lock() {
                let _ = file.write_all(message.as_bytes());
                let _ = file.flush();
                return;
            }
        }
        let _ = io::stderr().write_all(message.as_bytes());
    }));
    Ok(())
}

impl<'a> MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &self.0 {
            Some(file) => file
                .lock()
                .map_err(|_| io::Error::other("diagnostic log lock poisoned"))?
                .write(bytes),
            None => io::stderr().write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &self.0 {
            Some(file) => file
                .lock()
                .map_err(|_| io::Error::other("diagnostic log lock poisoned"))?
                .flush(),
            None => io::stderr().flush(),
        }
    }
}

struct RotatingFile {
    path: PathBuf,
    file: Option<File>,
    length: u64,
    limit: u64,
}

impl RotatingFile {
    fn open(path: &Path, limit: u64) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let length = file.metadata()?.len();
        let mut result = Self {
            path: path.to_owned(),
            file: Some(file),
            length,
            limit,
        };
        if length > limit {
            result.rotate()?;
            // A prior UI launch may have supplied an oversized file. Bound its
            // archive too, without retaining any other historical logs.
            OpenOptions::new()
                .write(true)
                .open(result.archive_path())?
                .set_len(limit)?;
        }
        Ok(result)
    }
    fn archive_path(&self) -> PathBuf {
        let mut archive = self.path.as_os_str().to_owned();
        archive.push(".1");
        PathBuf::from(archive)
    }
    fn rotate(&mut self) -> io::Result<()> {
        self.file.take();
        let operation = (|| {
            match std::fs::remove_file(self.archive_path()) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            std::fs::rename(&self.path, self.archive_path())
        })();
        // Reopen even after a rotation failure so one failed diagnostic write
        // cannot leave a permanently missing handle inside the sink.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.length = file.metadata()?.len();
        self.file = Some(file);
        operation
    }
}

impl Write for RotatingFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let retained = &bytes[..bytes.len().min(self.limit as usize)];
        if self.length.saturating_add(retained.len() as u64) > self.limit {
            self.rotate()?;
        }
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("diagnostic log unavailable"))?
            .write_all(retained)?;
        self.length += retained.len() as u64;
        // Very large individual events are truncated to the same hard bound.
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("diagnostic log unavailable"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_appends_then_keeps_only_one_bounded_archive() {
        let path = std::env::temp_dir().join(format!(
            "redirector-log-test-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"UI start\n").unwrap();
        let mut log = RotatingFile::open(&path, 32).unwrap();
        log.write_all(b"backend start\n").unwrap();
        log.flush().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "UI start\nbackend start\n"
        );
        log.write_all(&[b'a'; 32]).unwrap();
        log.write_all(&[b'b'; 64]).unwrap();
        log.flush().unwrap();
        let archive = log.archive_path();
        assert_eq!(std::fs::read(&archive).unwrap(), vec![b'a'; 32]);
        assert_eq!(std::fs::read(&path).unwrap(), vec![b'b'; 32]);
        drop(log);
        let mut reopened = RotatingFile::open(&path, 16).unwrap();
        assert_eq!(std::fs::metadata(&archive).unwrap().len(), 16);
        reopened.write_all(b"next\n").unwrap();
        drop(reopened);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(archive).unwrap();
    }
}
