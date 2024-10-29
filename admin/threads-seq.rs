#!/usr/bin/env -S cargo +nightly --quiet -Zscript

//! # `admin/thread-seq N`
//!
//! This program prints a sequence of N integers for multithreaded
//! performance testing.  The integers are numbers of threads to
//! be sampled in a test.  The goal is to assist in graphing
//! how per-thread throughput relates to concurrency.
//!
//! The sequence is (at most) length N, starts at 2, includes the
//! number of CPU cores, and ends at 1.5 the number of CPU cores.
//! It does not have repeated items.
//!
//! We exceed the number of cores specifically to see the
//! "elbow" in the graph, when the number of threads tested
//! exceeds the number of cores.  (This is good because otherwise
//! -- assuming the software under test is perfectly scalable --
//! the graph would be a straight line parallel with the x axis.)

use std::{cmp, env, error, num::NonZeroUsize, str::FromStr, thread};

fn main() -> Result<(), Box<dyn error::Error + Send + Sync + 'static>> {
    let mut args = env::args();
    args.next(); // skip argv[0]
    let count = args
        .next()
        .map(|c| NonZeroUsize::from_str(&c))
        .transpose()?
        .unwrap_or(NonZeroUsize::new(16).unwrap())
        .get();

    let default_cpus = thread::available_parallelism()?;
    let cpus = env::var("CPU_COUNT")
        .map(|c| NonZeroUsize::from_str(&c))
        .unwrap_or(Ok(default_cpus))?
        .get();

    let end = (cpus as f64 * 1.5).floor() as usize;

    let before_count = (count as f64 * 0.75).floor() as usize;
    let after_count = count - before_count;

    let before = (2..cpus).step_by(cmp::max(1, cpus / before_count));
    let after = (cpus..end).step_by(cmp::max(1, (end - cpus) / after_count));

    for x in before.chain(after) {
        print!("{} ", x);
    }
    println!();
    Ok(())
}
