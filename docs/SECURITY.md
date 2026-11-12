# net-io security

> Draft for `0.4.0`; final in `0.7.0`. The threat table below is the one net-io is built against. Each row names its defence, its cost, and the test that attacks it; a row whose feature ships later says when.

## Reporting a vulnerability

Email `me@jamesgober.com` with "net-io security" in the subject. Please do not open a public issue for a vulnerability. Expect an answer within a few days; fixes are released as patch versions with a note in `CHANGELOG.md`.

## Threat model

net-io is the first and last code every connection touches. Attackers range from scanners to botnets with residential proxies. net-io stops, on its own, the attacks that are transport problems, and makes the gate's enforcement impossible to skip.

Assets: descriptors, memory, worker threads, CPU, the integrity of the client address, the guarantee that no byte leaves a revoked connection, listening sockets during restarts, and local IPC endpoints.

Owned elsewhere: bans and rates (the gate, for example bouncer-io), content inspection, identity and authorization, floods larger than the link (upstream), and SYN floods (the kernel's SYN cookies).

## Threats, defences, tests

A cost marked `[est.]` is an estimate; the rest are measured, on the hosts `docs/PERFORMANCE.md` describes. Test names are `tests/<file>.rs::<name>` or `src/<file>.rs::<name>`.

| # | Threat | Defence | Cost | Test (status at 0.4) |
|---|---|---|---|---|
| T-1 | connection flood exhausting descriptors | global, per-listener, and per-source caps before any read; the gate before any read | 343 ns to take and release a source, on a loaded host; the 50 ns estimate was too low, and it is a small part of an accept | `server::test_global_cap_refuses_before_reading`, `server::test_per_source_cap`, `server::test_per_source_cap_per_listener` |
| T-2 | descriptor exhaustion making accept spin or stall | reserve descriptor, accept backoff | one spare descriptor per acceptor | `src/accept.rs::test_emfile_sheds_and_retries_the_reserve` |
| T-3 | slowloris | handshake and read deadlines, inbound minimum rate checked on every arrival and on a timer (D-138), exchange deadline | one timer per active connection; one rate check per receive [est. 10 to 20 ns] | `server::test_slow_peer_is_closed`, `server::test_trickle_faster_than_the_check_is_closed`, `src/rate.rs::test_rate_trickle_is_too_slow` |
| T-4 | slow read | write deadline, outbound minimum rate checked on every send completion and on a timer, output budget | as T-3 | `server::test_peer_that_never_reads_hits_the_write_timeout`, `server::test_reader_slower_than_the_rate_is_closed_while_it_reads` (Linux) |
| T-5 | idle keep-alive hoarding | idle deadline (5 s on the blocking driver) | none below pressure | `server::test_idle_timeout_closes`, `admission::test_pressure_shrinks_idle_deadlines_and_lets_go` |
| T-6 | a handshake that never finishes | one handshake deadline for PROXY and TLS | one timer | `proxy::test_missing_invalid_and_slow_headers`, `tls::test_refused_hello_and_handshake_timeout` |
| T-7 | memory exhaustion through many connections, including ones that never send a byte | buffer budget, per-connection output budget, pooled buffers that give the budget back above a fair share and across size classes; on the reactor no buffer before the first byte (TLS included), and unfinished TLS handshakes capped at a quarter of the budget (D-206) | none on the steady path; one zero-byte wait per TLS handshake | `src/buf.rs::test_pool_budget_bounds_allocation`, `src/buf.rs::test_take_frees_other_classes_for_the_charge`, `test_put_above_the_keep_limit_refunds_the_budget`, `tests/tls.rs::test_silent_tls_clients_do_not_stall_plaintext_connections`, `test_handshakes_holding_buffers_are_capped`, `tests/reactor.rs::test_buffers_one_class_freed_serve_another`; the 50,000-connection RSS test with the reactor (0.5) |
| T-8 | oversized PROXY header | 107-byte v1 cap; v2 length checked against the limit before the body is read | none | `src/proxy_parse.rs::test_v1_too_long`, `src/proxy_parse.rs::test_v2_errors` |
| T-9 | spoofed client address via PROXY from an untrusted peer | trust checked before the first read; an untrusted peer on a PROXY listener is closed unread | one set lookup | `proxy::test_untrusted_peer_is_closed_before_reading` |
| T-10 | missing PROXY header behind a proxy | `Required` fails closed; there is no optional mode | none | `proxy::test_missing_invalid_and_slow_headers` |
| T-11 | a PROXY header injected by a client through a proxy that does not strip it | exactly one header is read; a second one is application data | none | `src/proxy_parse.rs::test_second_header_is_data` |
| T-12 | PROXY v2 TLV bugs | bounds-checked walk, checked arithmetic, property tests, fuzzing | none | `src/proxy_parse.rs::prop_random_input_never_panics`; fuzz target `proxy` (CI, 30 s per push) |
| T-13 | framing someone else through a forged address | as T-9; `client_addr` and `client_key` use the PROXY address only from a trusted header | none | `src/info.rs::test_client_addr_prefers_real_peer`, `proxy::test_source_cap_moves_to_the_real_client` |
| T-14 | data leaving a revoked connection | the gate is asked before every write system call; abortive close on denial | one hook call per write | `close_reasons::reason_egress_denied`, `adopt::set_gate_checks_writes_and_closes_once`; wire capture in 0.7 |
| T-15 | a partial response leaking before a denial | denial bytes only before the response started | none | `close_reasons::reason_egress_denied` |
| T-16 | residual request data in reused buffers | wipe on release (default on) | 21.5 ns per 2 KiB, 127 ns per 16 KiB | `src/buf.rs::test_pool_reuses_and_wipes` |
| T-17 | kill races (double close, reused descriptor) | a closing flag set by compare-and-swap; only the owner closes; generations | one CAS per close | `src/sys/kill.rs` loom models, `edge::edge_129_kill_from_many_threads_closes_once` |
| T-18 | use after free on cancelled completions (IOCP, io_uring), or a packet the port did not start taken for one of its operations | an operation and its buffers are owned by the kernel until the packet is dequeued; the port keeps the address of every operation it started and skips any other packet; pipe IO outside the driver queues no packet (D-203) | a hash insert and remove per operation | `src/driver/iocp.rs::test_cancel_completes_once_with_the_buffer`, `test_stale_packet_is_dropped`, `test_blocked_send_cancels_with_its_chunks`, `src/sys/iocp.rs::test_a_foreign_packet_is_skipped`, `tests/pipe.rs::test_a_denial_to_a_pipe_client_that_does_not_read`; io_uring after 1.0 |
| T-19 | an accept storm starving established connections | accept batch per wake-up | none | `admission::test_accept_storm_leaves_established_connections_served` |
| T-20 | an offload flood filling completion queues | bounded ring, `Full`, park deadline | none | `src/completer.rs::test_ring_many_producers_never_exceeds_capacity` |
| T-21 | the event sink as a bottleneck | coalescing above 1,000 events per second per kind | one counter | `src/events.rs::test_coalescer_folds_above_threshold` |
| T-22 | hash flooding the per-source tables | SipHash with a random per-process key (`std`) | included in T-1's 343 ns | 0.7 (chain-length test) |
| T-23 | Unix socket hijack or eavesdropping | mode `0600` by default, set before `listen`; `bind_atomic`; `require_uid`; private directory guidance | one `getsockopt` per accept | `src/local.rs::test_bind_accept_echo_and_credentials`, `src/local.rs::test_require_uid_closes_other_users`, `unix::unix_listener_refuses_other_users_with_credentials_cause` |
| T-24 | stale-path deletion of a non-socket, or a mode or owner change redirected to another file (symlink or hard-link attack) | `lstat`; only a socket that refuses a probe connect is removed; mode and owner set by name relative to the open directory, or inside a private 0700 directory when others can change entries; a directory writable by others without the sticky bit refused (D-207) | one `lstat`, a directory open, one or two `*at` calls per bind | `src/local.rs::test_stale_socket_removed_live_one_refused`, `src/local.rs::test_longest_path_binds_and_non_sockets_stay`, `src/local.rs::test_drop_leaves_a_replacement_alone`, `src/local.rs::test_bind_refuses_a_directory_others_can_rename_in`, `src/local.rs::test_socket_swapped_for_a_link_never_changes_its_target` |
| T-25 | Linux abstract socket squatting | abstract names only with `require_uid` | one `getsockopt` | after 1.0 (`bind_abstract`, P3) |
| T-26 | named-pipe squatting, or a pipe name that reaches a file or a network path | names with no `\` or `/`, not `.` or `..`, at most 247 units (D-205); `FILE_FLAG_FIRST_PIPE_INSTANCE` whenever the listener holds no instance of its name; owner-only descriptor; clients can check the server's process and owner (`PipeConnection::server_pid`, `server_owner_sid`) | one uncontended lock per accept | `src/pipe.rs::test_security_keeps_this_user_out_when_told_to`, `src/pipe.rs::test_names_are_checked_before_any_call` |
| T-27 | a pipe client impersonated by a malicious server | `SECURITY_SQOS_PRESENT` with identification level | none | 0.5 |
| T-28 | remote access to a local pipe | `PIPE_REJECT_REMOTE_CLIENTS` always | none | 0.5 |
| T-29 | hand-off channel abuse | peer uid and pid, magic, version, length, CRC32C, descriptor count, per-descriptor verification against the manifest address, all or nothing | under 1 ms per hand-off [est.] | `src/handoff.rs::test_count_mismatch_truncation_timeout_and_peer`, `src/handoff.rs::test_address_must_match_the_manifest`, `src/handoff.rs::test_manifest_rejects_damage`; fuzz target `manifest` |
| T-30 | Windows hand-off to the wrong process, a forged one, or a replayed one | the sender must run as this user, have started before the pipe connected, and be the expected pid when one is given; target pid, single-use nonce; a socket that is not a fresh (inheritable) duplicate, or one already adopted (its flag is cleared at adoption), is refused and left as it was (D-204, D-210) | one lookup per hand-off, a few system calls per restart | `src/handoff.rs::test_a_hand_off_works_once`, `test_wrong_peer_and_bad_checksum`, `src/handoff.rs::test_a_socket_is_never_adopted_twice`, `test_a_description_naming_a_socket_owned_here_is_refused`, `test_a_forged_hand_off_neither_adopts_nor_closes_a_listener_here`, `test_a_forged_hand_off_leaves_other_handles_alone`, `test_only_a_sender_of_this_user_that_was_already_running_is_accepted` |
| T-31 | descriptor leak into child processes | close-on-exec on every socket and every received or inherited descriptor | none (macOS window documented below) | `src/sys/unix.rs::test_descriptors_cross_a_socket_pair` (received descriptors are close-on-exec), `leak::test_no_descriptor_leaks` |
| T-32 | `SIGPIPE` killing the process | `MSG_NOSIGNAL` (Linux), `SO_NOSIGPIPE` (macOS) | none | `edge::edge_21_22_peer_gone_mid_write_is_peer_reset_without_a_signal` |
| T-33 | systemd variables meant for another process | `LISTEN_PID`, `LISTEN_PIDFDID`, per-descriptor checks before any is taken | none | `src/inherit.rs::test_systemd_protocol`, `cross_process::systemd_socket_activation_with_the_real_tool`; fuzz target `systemd_env` |
| T-34 | descriptor 0 not a listening socket under FastCGI | listening check (`SO_ACCEPTCONN`, or no peer on macOS) | three system calls once | `src/inherit.rs::test_fastcgi_descriptor_checks`, `cross_process::fastcgi_listener_on_descriptor_zero` |
| T-35 | UDP amplification | replies to an unverified source never exceed `factor` (default 1) times what it sent within the window; sources keyed by address, not port | under 30 ns per send [est.] | `src/udp.rs::test_amplification_factor_one_until_verified`, `src/udp.rs::test_amplification_factor_three_and_the_window` |
| T-36 | UDP source flood and table exhaustion | per-source and global token buckets, a bounded table with CLOCK eviction of unverified entries, a shared overflow budget with no send allowance | under 30 ns per datagram [est.]; about 130 bytes per source | `src/udp.rs::test_source_budget_drops_and_others_pass`, `src/udp.rs::test_global_budget_caps_every_source`, `src/udp.rs::test_full_table_evicts_strangers_and_keeps_verified` |
| T-37 | a truncated datagram treated as complete | truncation always reported (`MSG_TRUNC`, `WSAEMSGSIZE`) | none | `src/udp.rs::test_echo_truncation_and_zero_length`, `src/sys/unix.rs::test_udp_recv_reports_truncation_and_source` |
| T-38 | port hijacking on Windows | `SO_EXCLUSIVEADDRUSE` by default (TCP and UDP) | none | `src/sys/windows.rs::test_listener_exclusive_by_default` |
| T-39 | a privileged port held while running as root | bind at `build`, drop privileges, then `open_door` | none | shield-sec integration |
| T-40 | a `Server` used after `fork` | creator pid checked on cold calls (`ForkedChild`) | one comparison | 0.7 (fork test) |
| T-41 | io_uring kernel attack surface | off by default, feature-gated, automatic fallback | none | after 1.0 |
| T-42 | timer storms caused by peers | lazy extension, intrusive slots, bounded expirations | none | 0.5 (the timing wheel) |
| T-43 | hello inspection bypassed by fragmenting the ClientHello | the engine reassembles within its bound; net-io's read buffer and handshake deadline bound it too | bounded | tls-net's tests; `tls::test_refused_hello_and_handshake_timeout` |
| T-44 | the refusal path used for amplification | at most 512 bytes, one non-blocking attempt, TCP after the handshake only | one system call | `src/gate.rs::test_refusal_code` and the refusal-bytes cap in `server` tests |
| T-45 | a gate or session panic letting traffic through | a gate panic refuses or denies; a session panic closes the connection | none | `src/gate.rs::test_gate_panic_in_check_denies`, `server::test_session_panic_is_contained` |

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

