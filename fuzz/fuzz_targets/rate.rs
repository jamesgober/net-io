//! The rate state machine: see `net_io::__fuzz::rate` for what it checks.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    net_io::__fuzz::rate(data);
});
