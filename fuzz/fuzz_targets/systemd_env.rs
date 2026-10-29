//! The systemd socket-activation reader with arbitrary `LISTEN_FDS`,
//! `LISTEN_FDNAMES`, and `LISTEN_PIDFDID` values (`LISTEN_PID` is this
//! process). Descriptors are looked for far above any open one, so nothing real
//! is touched; every outcome must be a value or an error, never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    net_io::__fuzz::systemd_env(data);
});
