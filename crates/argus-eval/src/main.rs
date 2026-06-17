//! Argus evaluation harnesses for the two thesis research questions.
//!
//! - `ff1` — correlation precision: does `match_confidence` predict true
//!   positives? (see [`ff1`])
//! - `ff2` — prioritisation: does the composite score beat a raw CVSS sort
//!   against the CISA KEV ground truth? (see [`ff2`])
//!
//! ```text
//! cargo run -p argus-eval            # run both on their embedded sample sets
//! cargo run -p argus-eval -- ff1     # FF1 only
//! cargo run -p argus-eval -- ff2 <file.csv>   # FF2 on your own dataset
//! ```

#![allow(clippy::cast_precision_loss)]

mod ff1;
mod ff2;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("ff1") => ff1::run(args.next()),
        Some("ff2") => ff2::run(args.next()),
        Some(other) => {
            eprintln!("unknown harness {other:?}; expected `ff1` or `ff2`");
            std::process::exit(2);
        }
        None => {
            ff1::run(None);
            println!("\n{}\n", "=".repeat(72));
            ff2::run(None);
        }
    }
}
