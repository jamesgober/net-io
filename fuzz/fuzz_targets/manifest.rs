//! The listener hand-off manifest decoder: arbitrary bytes must be refused with
//! an error, never a panic, and anything it accepts must re-encode identically.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    net_io::__fuzz::manifest(data);
});
