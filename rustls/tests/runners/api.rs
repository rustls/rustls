use std::cell::RefCell;

#[macro_use]
mod macros;

#[cfg(feature = "ring")]
#[path = "."]
mod tests_with_ring {
    use super::*;

    provider_ring!();

    #[path = "../api.rs"]
    mod tests;
}

#[cfg(feature = "aws-lc-rs")]
#[path = "."]
mod tests_with_aws_lc_rs {
    use super::*;

    provider_aws_lc_rs!();

    #[path = "../api.rs"]
    mod tests;
}

// this must be outside tests_with_*, as we want
// one thread_local!, not one per provider.
thread_local!(static COUNTS: RefCell<LogCounts> = RefCell::new(LogCounts::new()));

struct CountingLogger;

#[allow(dead_code)]
static LOGGER: CountingLogger = CountingLogger;

#[allow(dead_code)]
impl CountingLogger {
    fn install() {
        let _ = log::set_logger(&LOGGER);
        log::set_max_level(log::LevelFilter::Trace);
    }

    fn reset() {
        COUNTS.with(|c| {
            c.borrow_mut().reset();
        });
    }
}

impl log::Log for CountingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("logging at {:?}: {:?}", record.level(), record.args());

        COUNTS.with(|c| {
            c.borrow_mut()
                .add(record.level(), format!("{}", record.args()));
        });
    }

    fn flush(&self) {}
}

#[derive(Default, Debug)]
struct LogCounts {
    trace: Vec<String>,
    debug: Vec<String>,
    info: Vec<String>,
    warn: Vec<String>,
    error: Vec<String>,
}

impl LogCounts {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn add(&mut self, level: log::Level, message: String) {
        match level {
            log::Level::Trace => &mut self.trace,
            log::Level::Debug => &mut self.debug,
            log::Level::Info => &mut self.info,
            log::Level::Warn => &mut self.warn,
            log::Level::Error => &mut self.error,
        }
        .push(message);
    }
}
