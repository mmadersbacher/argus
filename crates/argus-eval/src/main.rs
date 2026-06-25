//! Argus evaluation harnesses for the two thesis research questions.
//!
//! - `ff1` — correlation precision: does `match_confidence` predict true
//!   positives? (see [`ff1`])
//! - `ff2` — prioritisation: does the composite score beat a raw CVSS sort
//!   against the CISA KEV ground truth? (see [`ff2`])
//! - `ff3` — measurable risk reduction: does acting on the prioritised plan make
//!   the network measurably safer, and is the reduction concentrated? (see
//!   [`ff3`])
//!
//! ```text
//! cargo run -p argus-eval            # run all three on their embedded samples
//! cargo run -p argus-eval -- ff1     # FF1 only
//! cargo run -p argus-eval -- ff2 <file.csv>   # FF2 on your own dataset
//! cargo run -p argus-eval -- ff3 <file.csv>   # FF3 on your own inventory
//! ```

#![allow(clippy::cast_precision_loss)]

mod ff1;
mod ff2;
mod ff3;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("ff1") => ff1::run(args.next()),
        Some("ff2") => ff2::run(args.next()),
        Some("ff3") => ff3::run(args.next()),
        Some(other) => {
            eprintln!("unknown harness {other:?}; expected `ff1`, `ff2` or `ff3`");
            std::process::exit(2);
        }
        None => {
            ff1::run(None);
            println!("\n{}\n", "=".repeat(72));
            ff2::run(None);
            println!("\n{}\n", "=".repeat(72));
            ff3::run(None);
        }
    }
}
