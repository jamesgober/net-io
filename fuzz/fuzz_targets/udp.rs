//! The UDP guard against a model: see `net_io::__fuzz::udp` for what it checks.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    net_io::__fuzz::udp(data);
});
