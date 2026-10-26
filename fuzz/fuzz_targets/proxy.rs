//! The PROXY protocol parser: arbitrary bytes, fed whole and in growing prefixes
//! the way a reader accumulates them. It must never panic, never claim more
//! bytes than it was given, and agree with itself across prefixes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use net_io::{ProxyParser, ProxyProgress, ProxyVersions};

fuzz_target!(|data: &[u8]| {
    let whole = ProxyParser::new(ProxyVersions::Both, 1024).feed(data).map(|p| match p {
        ProxyProgress::Done { header, consumed } => {
            assert!(consumed <= data.len());
            let _ = header.to_facts();
            let _ = (header.alpn(), header.authority(), header.unique_id(), header.ssl());
            for tlv in header.tlvs {
                let _ = tlv;
            }
            Some(consumed)
        }
        ProxyProgress::NeedMore { .. } => None,
    });
    let mut parser = ProxyParser::new(ProxyVersions::Both, 1024);
    let mut last = None;
    for end in 0..=data.len().min(256) {
        last = Some(parser.feed(&data[..end]).map(|p| match p {
            ProxyProgress::Done { consumed, .. } => Some(consumed),
            ProxyProgress::NeedMore { .. } => None,
        }));
        if matches!(last, Some(Ok(Some(_))) | Some(Err(_))) {
            break;
        }
    }
    // A complete header found in a prefix is the same header in the whole input.
    if let (Some(Ok(Some(n))), Ok(Some(m))) = (&last, &whole) {
        assert_eq!(n, m);
    }
});
