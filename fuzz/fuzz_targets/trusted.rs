//! Trusted-proxy lists: arbitrary text never panics, and every address in a
//! parsed list is trusted (checked on each block's network address).

#![no_main]

use libfuzzer_sys::fuzz_target;
use net_io::TrustedProxies;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(list) = TrustedProxies::parse(text) {
        assert!(list.len() <= TrustedProxies::MAX);
        for block in list.iter() {
            assert!(list.contains(block.network()));
        }
    }
});
