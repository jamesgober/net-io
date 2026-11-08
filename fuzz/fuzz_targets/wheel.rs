//! The wheel state machine: see `net_io::__fuzz::wheel` for what it checks.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    net_io::__fuzz::wheel(data);
});
