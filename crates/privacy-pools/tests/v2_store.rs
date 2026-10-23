//! `v2::CircuitStore`: the embedded catalog, what counts as missing, verified
//! installs, self-healing of corrupt files, and (with `download`) the HTTP path
//! against a local server. No network access.

use std::fs;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use privacy_pools::v2::{self, ArtifactKind, ArtifactSource, CircuitStore};
use privacy_pools::Error;
use serde_json::Value;

const COMMIT: &str = "1ee57b03a7a6a26a4bb70e9b3b49a4ca7fe2f6da";

fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/v2")
}

/// A fresh, empty store directory per test.
fn empty_store(name: &str) -> CircuitStore {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("v2-store-tests")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    CircuitStore::new(dir)
}

fn transact(inputs: u8, outputs: u8) -> v2::Circuit {
    v2::Circuit::Transact { inputs, outputs }
}

fn zkey_source(circuit: v2::Circuit) -> ArtifactSource {
    let [_, _, zkey] = ArtifactSource::all_for(circuit).unwrap();
    zkey
}

fn dir_entries(store: &CircuitStore) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(store.dir())
        .map(|it| {
            it.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn catalog_covers_all_27_with_pinned_github_sources() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(artifacts().join("manifest.json")).unwrap()).unwrap();
    let all: Vec<v2::Circuit> = v2::Circuit::all().collect();
    assert_eq!(all.len(), 27);
    assert_eq!(all.iter().filter(|c| c.is_bundled()).count(), 3);

    for c in all {
        let name = c.name();
        assert_eq!(v2::Circuit::from_name(&name), Some(c));
        let entry = &manifest["circuits"][&name];
        let signals: Vec<String> = serde_json::from_value(entry["public_signals"].clone()).unwrap();
        assert_eq!(c.public_signal_names(), signals, "{name}");
        assert_eq!(c.num_public(), signals.len(), "{name}");
        assert_eq!(entry["zkey"]["bundled"], c.is_bundled(), "{name}");

        let [graph, vkey, zkey] = ArtifactSource::all_for(c).unwrap();
        assert_eq!(
            (graph.kind, vkey.kind, zkey.kind),
            (ArtifactKind::Graph, ArtifactKind::Vkey, ArtifactKind::Zkey)
        );
        assert_eq!(graph.url, None, "graphs are ours; nobody hosts them");
        assert_eq!(
            zkey.url.as_deref(),
            Some(
                format!(
                    "https://media.githubusercontent.com/media/0xbow-io/privacy-pools-v2-monorepo/\
                     {COMMIT}/packages/circuits/build/{name}/groth16_pkey.zkey"
                )
                .as_str()
            )
        );
        assert_eq!(
            vkey.url.as_deref(),
            Some(
                format!(
                    "https://raw.githubusercontent.com/0xbow-io/privacy-pools-v2-monorepo/\
                     {COMMIT}/packages/circuits/build/{name}/groth16_vkey.json"
                )
                .as_str()
            )
        );
    }

    // Spot-check against upstream CEREMONY.md.
    let z = zkey_source(transact(3, 3));
    assert_eq!(
        z.sha256,
        "e1d7ce07915fad1d8d6562ef166a2fce981bdf211827a81f2ba3e029f7b01268"
    );
    assert_eq!(z.bytes, 41_469_005);
}

#[test]
fn unpublished_shapes_are_rejected() {
    let store = empty_store("unpublished");
    for (n, m) in [(0, 1), (6, 1), (1, 6)] {
        assert!(matches!(
            store.missing([transact(n, m)]),
            Err(Error::Input(_))
        ));
        assert!(matches!(store.prover(transact(n, m)), Err(Error::Input(_))));
        assert!(matches!(
            store.verifier(transact(n, m)),
            Err(Error::Input(_))
        ));
    }
}

#[test]
fn missing_lists_only_what_is_not_embedded_or_installed() {
    let store = empty_store("missing");
    let bundled: Vec<v2::Circuit> = v2::Circuit::all().filter(|c| c.is_bundled()).collect();
    let missing = store.missing([transact(3, 3), transact(3, 3)]).unwrap();

    if cfg!(feature = "partial-bundled-v2") {
        // Graphs + vkeys of all 27 and the bundled zkeys are embedded.
        assert!(store.missing(bundled.iter().copied()).unwrap().is_empty());
        assert_eq!(missing, vec![zkey_source(transact(3, 3))]);
        let all = store.missing(v2::Circuit::all()).unwrap();
        assert_eq!(all.len(), 24);
        assert!(all.iter().all(|s| s.kind == ArtifactKind::Zkey));
        assert_eq!(all.iter().map(|s| s.bytes).sum::<u64>(), 1_031_235_590);
        assert!(store.verifier(transact(5, 5)).is_ok(), "vkeys are embedded");
    } else {
        assert_eq!(
            missing,
            ArtifactSource::all_for(transact(3, 3)).unwrap().to_vec()
        );
        assert_eq!(store.missing(bundled).unwrap().len(), 9);
    }
    assert!(!store.is_available(transact(3, 3)).unwrap());
    assert!(matches!(
        store.prover(transact(3, 3)),
        Err(Error::CircuitNotDownloaded(name)) if name == "transact_3x3"
    ));
}

#[test]
fn install_verifies_size_and_sha256() {
    let store = empty_store("install");
    let source = zkey_source(v2::Circuit::Deposit);
    let bytes = fs::read(artifacts().join(&source.file)).unwrap();

    let mut tampered = bytes.clone();
    tampered[1000] ^= 1;
    assert!(matches!(
        store.install(&source, &tampered),
        Err(Error::Artifact(_))
    ));
    assert!(matches!(
        store.install(&source, &bytes[..bytes.len() - 1]),
        Err(Error::Artifact(_))
    ));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        store.install(&source, &longer),
        Err(Error::Artifact(_))
    ));
    assert!(
        dir_entries(&store).is_empty(),
        "failed installs leave nothing"
    );

    store.install(&source, &bytes).unwrap();
    assert_eq!(dir_entries(&store), ["deposit.zkey"]);
    assert_eq!(fs::read(store.dir().join("deposit.zkey")).unwrap(), bytes);
}

#[test]
fn install_reports_progress_and_can_be_cancelled() {
    let store = empty_store("cancel");
    let source = zkey_source(v2::Circuit::Deposit);
    let bytes = fs::read(artifacts().join(&source.file)).unwrap();

    let mut seen = Vec::new();
    store
        .install_from_reader(&source, bytes.as_slice(), |n| {
            seen.push(n);
            ControlFlow::Continue(())
        })
        .unwrap();
    assert!(seen.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(seen.last(), Some(&source.bytes));

    let store = empty_store("cancel-2");
    let result = store.install_from_reader(&source, bytes.as_slice(), |n| {
        if n > 100_000 {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(dir_entries(&store).is_empty());
}

/// A same-size corrupt file passes the cheap `missing` check, but `prover`
/// rejects it, deletes it, and it is reported missing again.
#[test]
fn corrupt_installed_file_is_rejected_and_removed() {
    let store = empty_store("corrupt");
    let first = store.missing([transact(3, 3)]).unwrap().remove(0);
    fs::create_dir_all(store.dir()).unwrap();
    fs::write(
        store.dir().join(&first.file),
        vec![0xAB; first.bytes as usize],
    )
    .unwrap();
    assert!(!store.missing([transact(3, 3)]).unwrap().contains(&first));

    assert!(matches!(
        store.prover(transact(3, 3)),
        Err(Error::Artifact(_))
    ));
    assert!(!store.dir().join(&first.file).exists());
    assert!(store.missing([transact(3, 3)]).unwrap().contains(&first));
}

// --- download (local HTTP server) -----------------------------------------------

/// Serve `body` with `status` for every request, until the test exits.
#[cfg(feature = "download")]
fn serve(status: u16, body: Vec<u8>) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    format!("http://{addr}/groth16_pkey.zkey")
}

#[cfg(feature = "download")]
fn with_url(mut source: ArtifactSource, url: String) -> ArtifactSource {
    source.url = Some(url);
    source
}

#[cfg(feature = "download")]
#[test]
fn download_streams_verifies_and_reports_progress() {
    let store = empty_store("download");
    let source = zkey_source(v2::Circuit::Deposit);
    let bytes = fs::read(artifacts().join(&source.file)).unwrap();
    let local = with_url(source.clone(), serve(200, bytes.clone()));
    let agent = privacy_pools::ureq::Agent::new_with_defaults();

    let mut progress = Vec::new();
    store
        .download_with(&agent, std::slice::from_ref(&local), |p| {
            progress.push((p.file_done, p.done, p.total));
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(fs::read(store.dir().join(&source.file)).unwrap(), bytes);
    assert!(progress.windows(2).all(|w| w[0].1 < w[1].1));
    assert_eq!(
        progress.last(),
        Some(&(source.bytes, source.bytes, source.bytes))
    );
}

#[cfg(feature = "download")]
#[test]
fn download_rejects_tampered_bytes_bad_status_and_cancel() {
    let store = empty_store("download-bad");
    let source = zkey_source(v2::Circuit::Deposit);
    let bytes = fs::read(artifacts().join(&source.file)).unwrap();
    let agent = privacy_pools::ureq::Agent::new_with_defaults();
    let go = |_: &v2::DownloadProgress| ControlFlow::Continue(());

    let mut tampered = bytes.clone();
    tampered[4242] ^= 0xff;
    let bad = with_url(source.clone(), serve(200, tampered));
    assert!(matches!(
        store.download_with(&agent, &[bad], go),
        Err(Error::Artifact(_))
    ));

    let not_found = with_url(source.clone(), serve(404, Vec::new()));
    assert!(matches!(
        store.download_with(&agent, &[not_found], go),
        Err(Error::Download(_))
    ));

    let ok = with_url(source.clone(), serve(200, bytes));
    assert!(matches!(
        store.download_with(&agent, &[ok], |_| ControlFlow::Break(())),
        Err(Error::Cancelled)
    ));

    let mut graph = ArtifactSource::all_for(transact(3, 3)).unwrap()[0].clone();
    graph.url = None;
    assert!(matches!(
        store.download_with(&agent, &[graph], go),
        Err(Error::Download(_))
    ));
    assert!(dir_entries(&store).is_empty());
}
