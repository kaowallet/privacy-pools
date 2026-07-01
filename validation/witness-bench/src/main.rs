//! Witness-generation benchmark: **our wasmer-free graph backend** vs the
//! **classic circom `.wasm` + wasmer** runtime.
//!
//! Proving (ark-groth16) is identical for both approaches, so the only place
//! the two paths differ is witness generation — that is what this measures, on
//! the real privacy-pools `commitment` and `withdraw` circuits, from the same
//! input JSON, with both circuits compiled at `--O1` (so the witness layouts
//! match). We also cross-check that both backends produce the *same* witness.
//!
//! Run:
//!   cargo run --release --manifest-path validation/witness-bench/Cargo.toml

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ark_circom::{Wasm, WitnessCalculator};
use num_bigint::{BigInt, BigUint};
use wasmer::{imports, Function, Instance, Memory, MemoryType, Module, Store};

/// Circuits to benchmark: (name, iterations). withdraw is ~10x heavier, so it
/// gets fewer iterations to keep the run snappy.
const CIRCUITS: &[(&str, usize)] = &[("commitment", 200), ("withdraw", 50)];

/// Warm-up iterations discarded before timing (JIT/cache warm-up, page-in).
const WARMUP: usize = 5;

fn main() -> Result<()> {
    let root = manifest_dir();
    let artifacts = root.join("../../crates/privacy-pools/artifacts");
    let fixtures = root.join("../../crates/privacy-pools/tests/fixtures");
    let assets = root.join("assets");

    println!("witness-generation benchmark — graph (wasmer-free) vs wasm+wasmer");
    println!("host: {} logical CPUs\n", num_cpus_hint());

    for &(name, iters) in CIRCUITS {
        let graph = std::fs::read(artifacts.join(format!("{name}.graph.bin")))
            .with_context(|| format!("reading {name}.graph.bin"))?;
        let wasm = assets.join(format!("{name}.wasm"));
        let inputs_json = std::fs::read_to_string(fixtures.join(format!("{name}_default.json")))
            .with_context(|| format!("reading {name}_default.json"))?;

        bench_circuit(name, iters, &graph, &wasm, &inputs_json)?;
        println!();
    }

    println!("notes:");
    println!("  • proving (ark-groth16) is identical for both paths and is excluded —");
    println!("    witness generation is the only step that differs.");
    println!("  • the graph per-witness time is if anything penalized: it re-parses the");
    println!("    graph every call, while wasm's module compile is a one-time setup cost.");
    Ok(())
}

fn bench_circuit(
    name: &str,
    iters: usize,
    graph: &[u8],
    wasm: &Path,
    inputs_json: &str,
) -> Result<()> {
    println!("── {name} ──");

    // ---- one-time setup cost, before the hot prove loop ----
    // Graph has no compile step: circom-witnesscalc re-parses the graph bytes on
    // every `calc_witness` call, so that cost is folded into per-witness below.
    // wasmer must JIT-compile the module once — the real cold-start cost.
    let (mut store, mut calc, wasm_setup) = {
        let start = Instant::now();
        let mut store = Store::default();
        let calc = build_calculator(&mut store, wasm)?;
        (store, calc, start.elapsed())
    };

    // Canonical (mod-p reduced) inputs, identical for both backends.
    let (canonical_json, wasm_inputs) = canonical_inputs(inputs_json)?;

    // Everything from here to the end of the timed loop is stdout-gagged:
    // circom-witnesscalc's `calc_witness` prints two timing lines per call.
    let (g, w, graph_w_len) = {
        let _gag = gag::Gag::stdout().ok();

        // ---- correctness: both backends must yield the same full witness ----
        let graph_w = graph_witness_decimal(&canonical_json, graph)?;
        let wasm_w = wasm_witness_decimal(&mut store, &mut calc, &wasm_inputs)?;
        if graph_w != wasm_w {
            drop(_gag);
            report_mismatch(&graph_w, &wasm_w);
            bail!("{name}: witness mismatch between graph and wasm backends");
        }

        // ---- warm-up ----
        for _ in 0..WARMUP {
            let _ = circom_witnesscalc::calc_witness(&canonical_json, graph)
                .map_err(|e| anyhow!("{e}"))?;
            let _ = calc
                .calculate_witness(&mut store, wasm_inputs.clone(), false)
                .map_err(|e| anyhow!("{e}"))?;
        }

        // ---- timed loops ----
        let mut graph_times = Vec::with_capacity(iters);
        let mut wasm_times = Vec::with_capacity(iters);
        for _ in 0..iters {
            let t = Instant::now();
            let _ = circom_witnesscalc::calc_witness(&canonical_json, graph)
                .map_err(|e| anyhow!("{e}"))?;
            graph_times.push(t.elapsed());

            let t = Instant::now();
            let _ = calc
                .calculate_witness(&mut store, wasm_inputs.clone(), false)
                .map_err(|e| anyhow!("{e}"))?;
            wasm_times.push(t.elapsed());
        }
        (
            Stats::from(&mut graph_times),
            Stats::from(&mut wasm_times),
            graph_w.len(),
        )
    };

    println!("  witness length: {graph_w_len} signals (backends agree ✔)");

    println!("  one-time setup:");
    println!("    graph   none (graph is (re)parsed inside each call below)");
    println!(
        "    wasm    {:>10}   (compile the .wasm module once)",
        fmt_dur(wasm_setup)
    );
    println!("  per-witness ({iters} iters, min / median / mean):");
    println!(
        "    graph   {:>10} / {:>10} / {:>10}",
        fmt_dur(g.min),
        fmt_dur(g.median),
        fmt_dur(g.mean)
    );
    println!(
        "    wasm    {:>10} / {:>10} / {:>10}",
        fmt_dur(w.min),
        fmt_dur(w.median),
        fmt_dur(w.mean)
    );
    let speedup = w.median.as_secs_f64() / g.median.as_secs_f64();
    let (faster, factor) = if speedup >= 1.0 {
        ("graph", speedup)
    } else {
        ("wasm", 1.0 / speedup)
    };
    println!("  → {faster} is {factor:.2}x faster per witness (median)");

    Ok(())
}

// ---------------------------------------------------------------------------
// Witness extraction as decimal strings (version-agnostic comparison boundary)
// ---------------------------------------------------------------------------

/// Run our graph backend and return the full witness as decimal strings.
fn graph_witness_decimal(inputs_json: &str, graph: &[u8]) -> Result<Vec<String>> {
    let wtns = circom_witnesscalc::calc_witness(inputs_json, graph)
        .map_err(|e| anyhow::anyhow!("calc_witness: {e}"))?;
    parse_wtns_decimal(&wtns)
}

/// Build an ark-circom `WitnessCalculator` over a circom `.wasm`, providing our
/// own wasmer import object.
///
/// We can't use `WitnessCalculator::new` directly: circom **2.2** emits a
/// `runtime.printDebug` import that ark-circom 0.6's built-in import set is
/// missing, so instantiation fails with "unknown import". We supply the full
/// runtime import set (no-op stubs — they only fire on debug/error paths, never
/// during a successful witness computation) and hand the instance to the public
/// `new_from_wasm` entry point. The wasmer runtime itself is unchanged, so this
/// measures the genuine wasmer witness-generation cost.
fn build_calculator(store: &mut Store, wasm: &Path) -> Result<WitnessCalculator> {
    let module = Module::from_file(&*store, wasm).context("compiling wasm module")?;
    // Same memory shape ark-circom uses internally (2000 pages, growable).
    let memory =
        Memory::new(&mut *store, MemoryType::new(2000, None, false)).context("creating memory")?;
    let import_object = imports! {
        "env" => { "memory" => memory },
        "runtime" => {
            "printDebug" => Function::new_typed(&mut *store, |_: i32| {}),
            "exceptionHandler" => Function::new_typed(&mut *store, |_: i32| {}),
            "printErrorMessage" => Function::new_typed(&mut *store, || {}),
            "writeBufferMessage" => Function::new_typed(&mut *store, || {}),
            "showSharedRWMemory" => Function::new_typed(&mut *store, || {}),
        }
    };
    let instance =
        Instance::new(&mut *store, &module, &import_object).context("instantiating wasm")?;
    WitnessCalculator::new_from_wasm(store, Wasm::new(instance))
        .map_err(|e| anyhow!("new_from_wasm: {e}"))
}

/// Run the wasmer backend and return the full witness as decimal strings.
fn wasm_witness_decimal(
    store: &mut Store,
    calc: &mut WitnessCalculator,
    inputs: &[(String, Vec<BigInt>)],
) -> Result<Vec<String>> {
    let w = calc
        .calculate_witness(store, inputs.to_vec(), false)
        .map_err(|e| anyhow::anyhow!("calculate_witness: {e}"))?;
    Ok(w.into_iter().map(|b| b.to_string()).collect())
}

/// Parse a snarkjs binary `.wtns` (v2) into decimal field-element strings.
/// Layout mirrors `privacy-pools`'s own parser: sections keyed by u32 id, the
/// header (id 1) carries `n8`, the data (id 2) is `nWitness × n8` little-endian.
fn parse_wtns_decimal(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() < 12 || &bytes[0..4] != b"wtns" {
        bail!("malformed .wtns: bad magic");
    }
    let n_sections = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mut off = 12usize;
    let mut n8: Option<usize> = None;
    let mut data: Option<(usize, usize)> = None;
    for _ in 0..n_sections {
        if off + 12 > bytes.len() {
            bail!("malformed .wtns: truncated section header");
        }
        let stype = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let slen = u64::from_le_bytes(bytes[off + 4..off + 12].try_into().unwrap()) as usize;
        let body = off + 12;
        if body + slen > bytes.len() {
            bail!("malformed .wtns: section overruns buffer");
        }
        match stype {
            1 => n8 = Some(u32::from_le_bytes(bytes[body..body + 4].try_into().unwrap()) as usize),
            2 => data = Some((body, slen)),
            _ => {}
        }
        off = body + slen;
    }
    let n8 = n8.context("missing header section")?;
    let (start, len) = data.context("missing witness section")?;
    if n8 == 0 || len % n8 != 0 {
        bail!("witness length not a multiple of field size");
    }
    Ok(bytes[start..start + len]
        .chunks_exact(n8)
        .map(|c| BigUint::from_bytes_le(c).to_string())
        .collect())
}

/// BN254 scalar field prime.
fn field_prime() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap()
}

/// Canonicalize the fixture into inputs both backends accept and agree on.
///
/// Returns `(canonical_json, wasm_inputs)` from the SAME reduced values, so the
/// two backends receive byte-identical inputs. Every value is reduced mod p:
/// the fixtures carry edge values like `label = 2^256-1` (valid for the typed
/// path, which reduces mod p, but rejected verbatim by `calc_witness`), and this
/// reduction matches exactly what the real prover feeds the circuit.
fn canonical_inputs(json: &str) -> Result<(String, Vec<(String, Vec<BigInt>)>)> {
    let p = field_prime();
    let val: serde_json::Value = serde_json::from_str(json).context("parsing input JSON")?;
    let obj = val.as_object().context("input JSON is not an object")?;

    let reduce = |v: &serde_json::Value| -> Result<BigUint> {
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            other => bail!("unexpected input value: {other}"),
        };
        let n = s
            .parse::<BigUint>()
            .with_context(|| format!("parsing field value `{s}`"))?;
        Ok(n % &p)
    };

    let mut json_obj = serde_json::Map::with_capacity(obj.len());
    let mut wasm = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        match v {
            serde_json::Value::Array(arr) => {
                let reduced: Vec<BigUint> = arr.iter().map(reduce).collect::<Result<_>>()?;
                json_obj.insert(
                    k.clone(),
                    serde_json::Value::Array(
                        reduced.iter().map(|n| n.to_string().into()).collect(),
                    ),
                );
                wasm.push((k.clone(), reduced.iter().map(to_bigint).collect()));
            }
            scalar => {
                let n = reduce(scalar)?;
                json_obj.insert(k.clone(), n.to_string().into());
                wasm.push((k.clone(), vec![to_bigint(&n)]));
            }
        }
    }
    let canonical_json = serde_json::to_string(&serde_json::Value::Object(json_obj))?;
    Ok((canonical_json, wasm))
}

fn to_bigint(n: &BigUint) -> BigInt {
    BigInt::from(n.clone())
}

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

struct Stats {
    min: Duration,
    median: Duration,
    mean: Duration,
}

impl Stats {
    fn from(times: &mut [Duration]) -> Self {
        times.sort_unstable();
        let min = times[0];
        let median = times[times.len() / 2];
        let sum: Duration = times.iter().sum();
        let mean = sum / times.len() as u32;
        Stats { min, median, mean }
    }
}

fn fmt_dur(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us >= 1000.0 {
        format!("{:.3} ms", us / 1000.0)
    } else {
        format!("{us:.1} µs")
    }
}

fn report_mismatch(a: &[String], b: &[String]) {
    eprintln!(
        "  witness MISMATCH: graph.len={}, wasm.len={}",
        a.len(),
        b.len()
    );
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x != y {
            eprintln!("    first diff at index {i}: graph={x} wasm={y}");
            break;
        }
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn num_cpus_hint() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
