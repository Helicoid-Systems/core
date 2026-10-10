//! Public-API check for the two coordinator review defects.
//!
//! This is not a platform proof. The authoritative regressions live in
//! `tests/review_regressions.rs`. This example exists so the exact
//! coordinator reproducer can be run against the built crate:
//!
//! ```text
//! cargo run --example repro_review
//! ```
//!
//! Expected output after the fix: both cases are rejected / exhausted.

fn main() {
    let empty = serde_json::from_str::<hs_core::ComputerId>("\"\"");
    match empty {
        Ok(v) => {
            eprintln!("FAIL: empty ComputerId deserialized to {:?}", v.as_str());
            std::process::exit(1);
        }
        Err(_) => println!("ok: empty ComputerId deserialize is rejected"),
    }

    let max = hs_core::DesktopGeneration(u64::MAX);
    match max.next() {
        Some(v) => {
            eprintln!("FAIL: exhausted generation saturated into {:?}", v);
            std::process::exit(1);
        }
        None => println!("ok: exhausted DesktopGeneration refuses reuse"),
    }

    println!("repro_review: both review defects are fixed");
}
