//! CIDR parsing: arbitrary text never panics, and a parsed block prints back to
//! text that parses to the same block.

#![no_main]

use libfuzzer_sys::fuzz_target;
use net_io::Cidr;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(cidr) = Cidr::parse(text) {
        let again = Cidr::parse(&cidr.to_string()).expect("a printed block parses");
        assert_eq!(cidr, again);
    }
});
