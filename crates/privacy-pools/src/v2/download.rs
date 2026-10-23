//! `download` feature: fetch missing v2 artifacts over HTTPS (ureq, blocking).
//!
//! Only call these from an explicit user action (e.g. a "download circuits"
//! prompt) — the SDK never fetches on its own. Run them off the UI thread.

use std::ops::ControlFlow;
use std::time::Duration;

use super::{ArtifactSource, Circuit, CircuitStore};
use crate::error::{Error, Result};

/// Download progress, reported after every received block.
#[derive(Clone, Copy, Debug)]
pub struct DownloadProgress<'a> {
    /// The file being fetched.
    pub source: &'a ArtifactSource,
    /// Bytes of `source` received so far.
    pub file_done: u64,
    /// Bytes received across the whole batch.
    pub done: u64,
    /// Total bytes in the batch.
    pub total: u64,
}

impl CircuitStore {
    /// Download everything `circuits` are [`missing`](Self::missing), one file
    /// at a time, verifying each against its pinned sha256. Pass
    /// [`Circuit::all()`] for the full set (~984 MB beyond the bundled three).
    ///
    /// `on_progress` returning `Break` cancels with [`Error::Cancelled`];
    /// files completed before that stay installed.
    pub fn download(
        &self,
        circuits: impl IntoIterator<Item = Circuit>,
        on_progress: impl FnMut(&DownloadProgress) -> ControlFlow<()>,
    ) -> Result<()> {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_connect(Some(Duration::from_secs(30)))
                .timeout_recv_response(Some(Duration::from_secs(60)))
                .build(),
        );
        self.download_with(&agent, &self.missing(circuits)?, on_progress)
    }

    /// Download `sources` with a caller-configured `agent` (proxy, Tor
    /// connector, timeouts, …).
    pub fn download_with(
        &self,
        agent: &ureq::Agent,
        sources: &[ArtifactSource],
        mut on_progress: impl FnMut(&DownloadProgress) -> ControlFlow<()>,
    ) -> Result<()> {
        let total = sources.iter().map(|s| s.bytes).sum();
        let mut done = 0;
        for source in sources {
            let url = source.url.as_deref().ok_or_else(|| {
                Error::Download(format!(
                    "{} is not hosted; build with `partial-bundled-v2` or stage it with \
                     `cargo xtask pull-circuits-v2`",
                    source.file
                ))
            })?;
            let response = agent
                .get(url)
                .call()
                .map_err(|e| Error::Download(format!("GET {url}: {e}")))?;
            let reader = response.into_body().into_reader();
            self.install_from_reader(source, reader, |file_done| {
                on_progress(&DownloadProgress {
                    source,
                    file_done,
                    done: done + file_done,
                    total,
                })
            })?;
            done += source.bytes;
        }
        Ok(())
    }
}
