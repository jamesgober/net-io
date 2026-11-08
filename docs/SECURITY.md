# net-io security

> Final as of `0.7.0`. The threat table below is the one net-io is built against. Each row names its defence, its cost, and the test that attacks it; a row whose feature ships later says when. `0.7.0` added T-46 to T-50 from the adversarial review of the whole crate (PLAN D-143 to D-160).

## Reporting a vulnerability

Email `me@jamesgober.com` with "net-io security" in the subject. Please do not open a public issue for a vulnerability. Expect an answer within a few days; fixes are released as patch versions with a note in `CHANGELOG.md`.

## Threat model

net-io is the first and last code every connection touches. Attackers range from scanners to botnets with residential proxies. net-io stops, on its own, the attacks that are transport problems, and makes the gate's enforcement impossible to skip.

Assets: descriptors, memory, worker threads, CPU, the integrity of the client address, the guarantee that no byte leaves a revoked connection, listening sockets during restarts, and local IPC endpoints.

Owned elsewhere: bans and rates (the gate, for example bouncer-io), content inspection, identity and authorization, floods larger than the link (upstream), and SYN floods (the kernel's SYN cookies).

## Threats, defences, tests

A cost marked `[est.]` is an estimate; the rest are measured, on the hosts `docs/PERFORMANCE.md` describes. Test names are `tests/<file>.rs::<name>` or `src/<file>.rs::<name>`.

| # | Threat | Defence | Cost | Test |
|---|---|---|---|---|
| T-1 | connection flood exhausting descriptors | global, per-listener, and per-source caps before any read; the gate before any read | 343 ns to take and release a source, on a loaded host; the 50 ns estimate was too low, and it is a small part of an accept | `server::test_global_cap_refuses_before_reading`, `server::test_per_source_cap`, `server::test_per_source_cap_per_listener` |
| T-2 | descriptor exhaustion making accept spin or stall | reserve descriptor, accept backoff | one spare descriptor per acceptor | `src/accept.rs::test_emfile_sheds_and_retries_the_reserve` |
| T-3 | slowloris | handshake and read deadlines, inbound minimum rate checked on every arrival and on a timer (D-138), exchange deadline | one timer per active connection; one rate check per receive [est. 10 to 20 ns] | `server::test_slow_peer_is_closed`, `server::test_trickle_faster_than_the_check_is_closed`, `src/rate.rs::test_rate_trickle_is_too_slow` |
| T-4 | slow read | write deadline, outbound minimum rate checked on every send completion and on a timer, output budget | as T-3 | `server::test_peer_that_never_reads_hits_the_write_timeout`, `server::test_reader_slower_than_the_rate_is_closed_while_it_reads` (Linux) |
| T-5 | idle keep-alive hoarding | idle deadline (5 s on the blocking driver) | none below pressure | `server::test_idle_timeout_closes`, `admission::test_pressure_shrinks_idle_deadlines_and_lets_go` |
| T-6 | a handshake that never finishes | one handshake deadline for PROXY and TLS | one timer | `proxy::test_missing_invalid_and_slow_headers`, `tls::test_refused_hello_and_handshake_timeout` |
| T-7 | memory exhaustion through many connections | buffer budget, per-connection output budget, pooled buffers | none | `src/buf.rs::test_pool_budget_bounds_allocation`; the 50,000-connection RSS test with the reactor (0.5) |
| T-8 | oversized PROXY header | 107-byte v1 cap; v2 length checked against the limit before the body is read | none | `src/proxy_parse.rs::test_v1_too_long`, `src/proxy_parse.rs::test_v2_errors` |
| T-9 | spoofed client address via PROXY from an untrusted peer | trust checked before the first read; an untrusted peer on a PROXY listener is closed unread | one set lookup | `proxy::test_untrusted_peer_is_closed_before_reading` |
| T-10 | missing PROXY header behind a proxy | `Required` fails closed; there is no optional mode | none | `proxy::test_missing_invalid_and_slow_headers` |
| T-11 | a PROXY header injected by a client through a proxy that does not strip it | exactly one header is read; a second one is application data | none | `src/proxy_parse.rs::test_second_header_is_data` |
| T-12 | PROXY v2 TLV bugs | bounds-checked walk, checked arithmetic, property tests, fuzzing | none | `src/proxy_parse.rs::prop_random_input_never_panics`; fuzz target `proxy` (CI, 30 s per push) |
| T-13 | framing someone else through a forged address | as T-9; `client_addr` and `client_key` use the PROXY address only from a trusted header | none | `src/info.rs::test_client_addr_prefers_real_peer`, `proxy::test_source_cap_moves_to_the_real_client` |
| T-14 | data leaving a revoked connection | the gate is asked before every write system call; abortive close on denial | one hook call per write | `close_reasons::reason_egress_denied`, `adopt::set_gate_checks_writes_and_closes_once`, `close_reasons::test_revoked_stream_sends_nothing_past_the_approval` (wire capture, both drivers) |
| T-15 | a partial response leaking before a denial | denial bytes only before the response started; under TLS the denial is an encrypted record, never plaintext on the socket | none; one encryption per denial under TLS | `close_reasons::reason_egress_denied`, `tls::test_denial_under_tls_is_encrypted` |
| T-16 | residual request data in reused buffers | wipe on release (default on), covering every byte the buffer held since its last wipe, not only its current length | 21.5 ns per 2 KiB, 127 ns per 16 KiB held | `src/buf.rs::test_pool_reuses_and_wipes`, `src/buf.rs::test_pool_wipes_what_a_shorter_len_left_behind` |
| T-17 | kill races (double close, reused descriptor) | a closing flag set by compare-and-swap; only the owner closes; generations | one CAS per close | `src/sys/kill.rs` loom models, `edge::edge_129_kill_from_many_threads_closes_once` |
| T-18 | use after free on cancelled completions (IOCP, io_uring) | an operation and its buffers are owned by the kernel until the packet is dequeued | none | `src/driver/iocp.rs::test_cancel_completes_once_with_the_buffer`, `test_stale_packet_is_dropped`, `test_blocked_send_cancels_with_its_chunks`; io_uring after 1.0 |
| T-19 | an accept storm starving established connections | accept batch per wake-up | none | `admission::test_accept_storm_leaves_established_connections_served` |
| T-20 | an offload flood filling completion queues | bounded ring, `Full`, park deadline | none | `src/completer.rs::test_ring_many_producers_never_exceeds_capacity` |
| T-21 | the event sink as a bottleneck | coalescing above 1,000 events per second per kind | one counter | `src/events.rs::test_coalescer_folds_above_threshold` |
| T-22 | hash flooding the per-source tables | SipHash with a random key per table (`std`); the table is sharded and sized from the cap, at most 8,192 entries a shard up front | included in T-1's 343 ns | `src/server/source.rs::test_source_keys_spread_over_shards_and_hash_per_table` |
| T-23 | Unix socket hijack or eavesdropping | mode `0600` by default, set before `listen`; `bind_atomic`; `require_uid`; private directory guidance | one `getsockopt` per accept | `src/local.rs::test_bind_accept_echo_and_credentials`, `src/local.rs::test_require_uid_closes_other_users`, `unix::unix_listener_refuses_other_users_with_credentials_cause` |
| T-24 | stale-path deletion of a non-socket (symlink attack) | `lstat`; only a socket that refuses a probe connect is removed; identity checked around `chmod` | one `lstat` | `src/local.rs::test_stale_socket_removed_live_one_refused`, `src/local.rs::test_longest_path_binds_and_non_sockets_stay`, `src/local.rs::test_drop_leaves_a_replacement_alone` |
| T-25 | Linux abstract socket squatting | abstract names only with `require_uid` | one `getsockopt` | after 1.0 (`bind_abstract`, P3) |
| T-26 | named-pipe squatting | `FILE_FLAG_FIRST_PIPE_INSTANCE` whenever the listener holds no instance of its name; owner-only descriptor; clients can check the server's process and owner (`PipeConnection::server_pid`, `server_owner_sid`) | one uncontended lock per accept | `src/pipe.rs::test_accept_never_joins_a_pipe_made_in_the_gap`, `src/pipe.rs::test_client_checks_the_server`, `src/pipe.rs::test_security_keeps_this_user_out_when_told_to` |
| T-27 | a pipe client impersonated by a malicious server | `SECURITY_SQOS_PRESENT` with identification level | none | `src/sys/pipe.rs::test_constants_match_windows_sys` |
| T-28 | remote access to a local pipe | `PIPE_REJECT_REMOTE_CLIENTS` always | none | `src/sys/pipe.rs::test_constants_match_windows_sys` |
| T-29 | hand-off channel abuse | peer uid and pid, magic, version, length, CRC32C, descriptor count, per-descriptor verification against the manifest address, all or nothing | under 1 ms per hand-off [est.] | `src/handoff.rs::test_count_mismatch_truncation_timeout_and_peer`, `src/handoff.rs::test_address_must_match_the_manifest`, `src/handoff.rs::test_manifest_rejects_damage`; fuzz target `manifest`, `src/sys/unix.rs::test_cut_record_closes_the_descriptors_it_holds` (every descriptor of a cut message closed), `src/sys/unix.rs::test_listener_kind_keeps_abstract_names` |
| T-30 | Windows hand-off to the wrong process, or a replayed hand-off | target pid, the pipe's far-end pid, single-use nonce; every description claimed before any is verified, and a socket already owned here refused | one lookup per hand-off | `src/handoff.rs::test_a_hand_off_works_once`, `test_wrong_peer_and_bad_checksum`, `src/handoff.rs::test_a_socket_is_never_adopted_twice`, `src/handoff.rs::test_a_failed_hand_off_leaves_no_socket_open` |
| T-31 | descriptor leak into child processes | close-on-exec on every socket and every received or inherited descriptor (atomic on Linux and FreeBSD); on Windows, sockets received through hand-off made non-inheritable | none (macOS window documented below) | `src/sys/unix.rs::test_descriptors_cross_a_socket_pair` (received descriptors are close-on-exec), `leak::test_no_descriptor_leaks`, `src/handoff.rs::test_received_sockets_are_not_inheritable` |
| T-32 | `SIGPIPE` killing the process | `MSG_NOSIGNAL` (Linux), `SO_NOSIGPIPE` (macOS) | none | `edge::edge_21_22_peer_gone_mid_write_is_peer_reset_without_a_signal` |
| T-33 | systemd variables meant for another process | `LISTEN_PID`, `LISTEN_PIDFDID`, per-descriptor checks before any is taken; a descriptor with close-on-exec set cannot have crossed `execve` and is not taken | none | `src/inherit.rs::test_systemd_protocol`, `cross_process::systemd_socket_activation_with_the_real_tool`; fuzz target `systemd_env`, `src/inherit.rs::test_close_on_exec_descriptors_are_not_inherited` |
| T-34 | descriptor 0 not a listening socket under FastCGI | listening check (`SO_ACCEPTCONN`, or no peer on macOS) | three system calls once | `src/inherit.rs::test_fastcgi_descriptor_checks`, `cross_process::fastcgi_listener_on_descriptor_zero` |
| T-35 | UDP amplification | replies to an unverified source never exceed `factor` (default 1) times what it sent within the window; sources keyed by address, not port; verification covers one address and port for `verification_lifetime` (60 s) from the latest proof, in its own bounded table | under 30 ns per send [est.], one more lookup per unverified send | `src/udp.rs::test_amplification_factor_one_until_verified`, `src/udp.rs::test_amplification_factor_three_and_the_window`, `src/udp.rs::test_verification_is_per_port_and_expires`, `src/udp.rs::test_verified_port_does_not_cover_the_ip` |
| T-36 | UDP source flood and table exhaustion | per-source and global token buckets, a bounded table with CLOCK eviction in which only an admitted datagram counts as use and a full table's own traffic turns the hand, a shared overflow budget with no send allowance, verified peers in a separate bounded table | under 30 ns per datagram [est.]; about 130 bytes per source | `src/udp.rs::test_source_budget_drops_and_others_pass`, `src/udp.rs::test_global_budget_caps_every_source`, `src/udp.rs::test_dropped_datagrams_do_not_keep_entries`, `src/udp.rs::test_full_table_traffic_turns_the_hand`, `src/udp.rs::test_verified_peers_leave_room_for_newcomers` |
| T-37 | a truncated datagram treated as complete | truncation always reported (`MSG_TRUNC`, `WSAEMSGSIZE`) | none | `src/udp.rs::test_echo_truncation_and_zero_length`, `src/sys/unix.rs::test_udp_recv_reports_truncation_and_source` |
| T-38 | port hijacking on Windows | `SO_EXCLUSIVEADDRUSE` by default (TCP and UDP) | none | `src/sys/windows.rs::test_listener_exclusive_by_default` |
| T-39 | a privileged port held while running as root | bind at `build`, drop privileges, then `open_door` | none | shield-sec integration |
| T-40 | a `Server` used after `fork` | creator pid checked on cold calls (`ForkedChild`) | one comparison | `fork::test_server_in_a_forked_child_refuses_cold_calls` (a real `fork`) |
| T-41 | io_uring kernel attack surface | off by default, feature-gated, automatic fallback | none | after 1.0 |
| T-42 | timer storms caused by peers | lazy extension, intrusive slots, bounded expirations; a clock that goes back cannot spin the wheel | none | `src/wheel.rs::test_extended_a_million_times_fires_once`, `test_many_timers_in_one_slot_are_bounded_by_the_caller`, `test_clock_going_back_does_not_spin`; fuzz target `wheel` |
| T-43 | hello inspection bypassed by fragmenting the ClientHello | the engine reassembles within its bound; net-io's read buffer and handshake deadline bound it too | bounded | tls-net's tests; `tls::test_refused_hello_and_handshake_timeout` |
| T-44 | the refusal path used for amplification | at most 512 bytes, one non-blocking attempt, TCP after the handshake only | one system call | `src/gate.rs::test_refusal_code` and the refusal-bytes cap in `server` tests |
| T-45 | a gate or session panic letting traffic through | a gate panic refuses or denies; a session panic closes the connection | none | `src/gate.rs::test_gate_panic_in_check_denies`, `server::test_session_panic_is_contained` |
| T-46 | a TLS engine or event sink bug turning one connection into a lost worker (caps, `busy`, and drains held for ever) | every engine call behind a panic boundary (a panic becomes `TlsFailed`); every sink call guarded; a last boundary in each worker that closes what a panic left and returns its caps | none unless a panic unwinds | `tls::test_engine_panic_closes_only_that_connection`, `server::test_panicking_event_sink_loses_only_its_events` |
| T-47 | bytes sent with a PROXY header reaching a TLS session as if decrypted (command injection, the STARTTLS class) | read-ahead after a PROXY header moves into the engine's input when TLS attaches; the reactor never delivers read-ahead under TLS | one copy of what was read ahead | `tls::test_proxy_then_tls_on_sessions_feeds_read_ahead_to_the_engine` |
| T-48 | a file stream to a fast reader holding a reactor worker | at most 256 KiB of file between two looks at the OS, in 256 KiB pieces | about 2 us per 256 KiB [est. under 3%] | `shim::test_file_stream_looks_at_the_os_every_256_kib`, `bulk::test_bulk_stream_leaves_small_exchanges_their_latency` |
| T-49 | TLS records with no plaintext, or records the engine sends on its own, keeping a connection past its idle deadline or its minimum rate | any ciphertext starts an exchange; engine records never end one; the handshake flight is bound by the handshake deadline | none | `tls::test_handshake_flight_is_bounded_by_the_handshake_deadline` |
| T-50 | configuration that panics or lifts a cap (a timeout of `Duration::MAX`, a listener's own global cap) | timeouts over a year and caps over 2^20 refused at build; durations at call sites held to a year; a listener caps itself with `max_per_listener` only | none | `src/limits.rs::test_timeouts_over_a_year_and_huge_caps_rejected`, `server::test_duration_max_is_held_to_a_year_not_a_panic`, `server::test_listener_cannot_set_the_global_cap` |
| T-51 | a stale socket number reaching another connection through the public `Driver` (safe code dropped a registered socket) | the driver holds each registered socket (`SharedSocket`) until `deregister` | one `Arc` per registration | `driver::test_registration_keeps_the_socket_until_deregister` |
| T-52 | removing a reparse point that is not a socket when binding an AF_UNIX path on Windows (a cloud placeholder, an app alias) | only a reparse point tagged as an AF_UNIX socket file is removed | one open and query per bind on an existing path | `windows_unix::test_other_reparse_points_stay` |

## What net-io does not cover

- Bytes already handed to the kernel cannot be recalled: all-or-nothing responses must be complete before they are written.
- SYN floods are the kernel's job (SYN cookies); net-io cannot see half-open connections.
- Floods larger than the link need upstream help.
- A compromised trusted proxy can claim any client address. Keep the trusted list minimal; on a Unix listener the socket file's mode is the trust boundary.
- macOS has no atomic close-on-exec for accepted, received, or inherited descriptors: a child created by another thread between the system call and `fcntl(FD_CLOEXEC)` can inherit one.
- Policy (who is banned, which rate) belongs to the gate. net-io's per-source cap is a concurrency cap only, and a Unix listener has no source address to cap.
- The UDP guard limits what net-io sends; a protocol that sends through another path is not covered.

## Hardening checklist for deployments

- Bind privileged ports at `build`, drop privileges, then call `open_door`.
- Keep Unix sockets and the hand-off channel in a private directory (`0700`); use `group_access` or `require_uid` rather than wider modes.
- Set `trusted_proxies` per listener to exactly the proxies in front of it.
- Keep buffer wiping on (the default) unless measurements show it matters and no secrets pass through.
- Send net-io's events to a sink that alerts on `DescriptorPressure`, `ListenerFailed`, and floods of `Refused`.

## Reactor and Windows additions (0.5)

| Measure | Cost | Test |
|---|---|---|
| An idle connection pins no buffer, in any phase, so a silent peer costs state only | one more system call per wake-up on Windows; none on epoll or kqueue | `tests/idle.rs`, `tests/reactor.rs` |
| An empty buffer budget pauses reads instead of failing the connection; the read deadline keeps running | one list entry; a 10 ms retry on that worker while anything waits | `reactor::test_buffer_budget_pauses_reading` |
| A listener never joins a completion port (D-016), enforced by the driver | one `getsockopt` per registration [est. under 1 us] | `src/driver/iocp.rs::test_listener_is_refused` |
| Named pipes reject remote clients, are owner-only by default, and detect a squatter through the first instance | one token query per listener | `src/pipe.rs::test_name_in_use_and_next_instance`, `test_security_keeps_this_user_out_when_told_to` |
| A pipe server can identify a client and cannot impersonate it | none | by the client's `SECURITY_IDENTIFICATION` flag |
| Windows AF_UNIX refuses mode and owner options rather than ignoring them | none | `windows_unix::test_options_that_do_not_apply_are_refused` |

## Optimisation additions (0.6)

| Measure | Cost | Test |
|---|---|---|
| A file that ends early resets the connection with `Io(FileTruncated)`: the peer was promised a length, and a clean close would read as a complete response | none until it happens | `send_file::test_push_file_that_ends_early_resets_on_both_drivers` |
| The gate checks a file 1 MiB at a time, so a revoked connection stops within that much | one check per MiB | `send_file::test_gate_counts_file_bytes_once_on_both_drivers` |
| `fast_open` is off by default: data in a SYN can be replayed, and it arrives before the peer's address is proven. A deployment that turns it on must treat first-flight requests as replayable | one socket option | `src/tcp.rs::test_fast_open_listener_still_accepts` |
| Deadlines shrink under `Pressure`, floor 1 s, with hysteresis, so an idle hoarder gives way first | one walk of the connections per crossing | `admission::test_pressure_shrinks_idle_deadlines_and_lets_go` |
| `lane_reserve` keeps slots for the more important lanes | one comparison after the gate | `admission::test_lane_reserve_keeps_slots_for_the_more_important` |
| `lockdown_allowed` keeps a named listener open through lockdown, for an admin path | one comparison per accept | `admission::test_lockdown_leaves_the_allowed_listener_open` |
| A UDP session runs behind the same amplification guard as a socket | as T-35 | `udp_session::test_door_and_guard` |

The moved-buffer path allocates nothing after warm-up (D-134), so a client cannot drive allocation by sending full buffers; `tests/alloc.rs` checks it on every driver.

