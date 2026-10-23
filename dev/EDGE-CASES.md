# net-io - Edge cases and their tests

> Every case in [`PLAN.md`](./PLAN.md) appendix A has a test by the version that ships the feature it concerns. This file maps each case to its tests, or to the version that ships it with the reason. Updated with every version.

Test locations: `tests/<file>.rs::<name>`, unit tests as `src/<file>.rs::<name>`. `shim` tests need `--cfg net_io_shim`; `loom_` tests need `--cfg loom`.

## Reads

| Case | Tests (0.3) |
|---|---|
| 1. EOF in Idle: `PeerClosed` | `edge::edge_01_eof_in_idle_is_peer_closed`, `close_reasons::reason_peer_closed` |
| 2. EOF in Receiving reaches the session | `edge::edge_02_37_eof_mid_request_reaches_the_session_which_may_still_write` |
| 3. Partial reads at every split | `edge::edge_03_partial_reads_at_every_split` |
| 4. Full buffer, nothing consumed: `Limit(ReadBuffer)`, no spin | `edge::edge_04_full_buffer_with_nothing_consumed_is_a_limit_not_a_spin`, `close_reasons::reason_limit_read_buffer` |
| 5. `EINTR` retried | `shim::test_interrupted_receives_are_retried`, `src/sys/mod.rs::test_retry_interrupted_retries_then_returns` |
| 6. Spurious `EAGAIN` retried | `shim::test_spurious_would_block_is_retried` |
| 7. `ECONNRESET`: `PeerReset` | `edge::edge_07_33_peer_reset_is_peer_reset`, `close_reasons::reason_peer_reset`, `shim::test_receive_error_closes_only_that_connection` |
| 8. Keepalive `ETIMEDOUT`: `Io(TimedOut)` | `shim::test_keepalive_timeout_is_an_io_error_not_a_deadline` (D-080) |
| 9. Data after our `shutdown(Read)` never delivered | `server::test_kill_ends_a_blocked_handler`, `src/tcp.rs::test_kill_wakes_blocked_recv` |
| 10. Data while parked read after the wake | `edge::edge_10_bytes_sent_while_parked_are_read_after_the_wake` |
| 11. Buffer budget exhausted: reading pauses | 0.5. The blocking driver takes each worker's buffers at warm-up and validates the budget at build, so it never runs dry mid-connection; pausing a connection's reads applies to the reactor |
| 12. Zero-length `recv` | `edge::edge_12_zero_length_receive_returns_at_once` |
| 13 to 17. PROXY header cases | 0.4 (the PROXY listener ships then) |

## Writes

| Case | Tests (0.3) |
|---|---|
| 18. Partial writes from the exact offset | `shim::test_partial_writes_at_many_splits`, `shim::test_short_writes_still_deliver_everything`, `src/session.rs::prop_output_stream_matches_accepted_pushes` |
| 19. `send` returns 0: full once, then an error | `shim::test_zero_byte_send_once_then_error` (D-074) |
| 20. `EAGAIN`: wait within the write deadline | `server::test_sessions_echo_large_message`, `edge::edge_25_32_large_response_after_peer_fin_uses_several_checked_sends` |
| 21. `EPIPE` without a signal | `edge::edge_21_22_peer_gone_mid_write_is_peer_reset_without_a_signal` |
| 22. `ECONNRESET` mid-write: `PeerReset`, output released | `edge::edge_21_22_peer_gone_mid_write_is_peer_reset_without_a_signal` |
| 23. Write deadline: `WriteTimeout` | `server::test_peer_that_never_reads_hits_the_write_timeout`, `close_reasons::reason_write_timeout` |
| 24. Vectored write partly into a later slice | `src/session.rs::prop_output_stream_matches_accepted_pushes`, `src/session.rs::test_output_advance_releases_chunks` |
| 25. Several system calls, each after a gate check | `edge::edge_25_32_large_response_after_peer_fin_uses_several_checked_sends` |
| 26. Denial between two chunks of a response: RST, no denial | `edge::edge_26_denial_inside_a_response_resets_without_a_denial` |
| 27, 28. Denial before the first byte: written once, not checked again | `edge::edge_27_28_denial_before_the_first_byte_is_written_once`, `close_reasons::reason_egress_denied` |
| 29. Output budget full: `OutputFull`, `Step::Write` | `server::test_sessions_echo_large_message`, `src/session.rs::test_output_push_all_or_nothing_and_partial` |
| 30. `sendfile` short or file shrinks | 0.6 (`send_file` and `Output::push_file` ship then) |
| 31. TLS ciphertext over the budget | 0.4 (the TLS seam is wired then) |

## Close

| Case | Tests (0.3) |
|---|---|
| 32. Peer FIN with output pending: finish, then close | `edge::edge_25_32_large_response_after_peer_fin_uses_several_checked_sends` |
| 33. Peer RST while we write | `edge::edge_07_33_peer_reset_is_peer_reset`, `edge::edge_21_22_peer_gone_mid_write_is_peer_reset_without_a_signal` |
| 34. Graceful close with unread input lingers | `edge::edge_34_close_with_unread_input_lingers_so_the_reply_arrives` |
| 35. Abort sends RST | `edge::edge_35_abort_sends_a_reset` |
| 36. Kill during the linger | `edge::edge_36_kill_during_the_linger_closes_at_once` |
| 37. Half-closed peer keeps reading | `edge::edge_02_37_eof_mid_request_reaches_the_session_which_may_still_write`, `edge::edge_25_32_large_response_after_peer_fin_uses_several_checked_sends` |
| 38, 39. `shutdown(Write)` twice; close after the peer closed | `edge::edge_38_39_shutdown_twice_and_close_after_the_peer_closed` |

## Accept

| Case | Tests (0.3) |
|---|---|
| 40, 41. `EMFILE` with the reserve; reserve not reopened | `src/accept.rs::test_emfile_sheds_and_retries_the_reserve`, `shim::test_accept_out_of_descriptors_recovers` |
| 42, 45. `ENFILE`, `ENOBUFS`, `ENOMEM`: pause, resume | `shim::test_accept_resource_errors_pause_then_resume` |
| 43, 44. `ECONNABORTED`, `EPERM`: counted, continue | `shim::test_accept_per_connection_errors_continue` |
| 46. `EBADF` / `EINVAL`: listener failed, no spin | `shim::test_accept_listener_failure_stops_without_spinning` |
| 47. Unspecified peer address | `src/accept.rs::test_unspecified_or_portless_peer_is_not_usable` (D-070; loopback cannot produce one) |
| 48. A burst in the backlog does not stall IO | `edge::edge_48_burst_in_the_backlog_does_not_stall_open_connections` |
| 49. Door closed with a backlog: kept, or reset by `shutdown` | `server::test_closed_door_leaves_connections_in_the_backlog`, `edge::edge_49_backlog_is_reset_by_shutdown` |
| 50. Handed-off listener's backlog unknown | 0.4 (hand-off ships then) |
| 51. IPv4-mapped peer normalized before caps and the gate | `edge::edge_51_mapped_peer_is_normalized_before_the_gate`, `src/addr.rs::test_normalize_mapped_v6_becomes_v4` |
| 52. Scope id kept; the prefix key ignores it | `src/addr.rs::test_normalize_socket_keeps_port_and_scope` (`PrefixKey::of` takes an `IpAddr`, which has no scope id) |

## Timers

| Case | Tests |
|---|---|
| 53 to 60. Wheel cases | 0.5, with the timing wheel (D-063) |
| 61. Tick coarser than a deadline: rejected at build | `src/limits.rs::test_timeout_below_tick_rejected` |

## IOCP, io_uring, Unix sockets, named pipes, UDP, hand-off (62 to 105)

Ship with those features: Unix sockets, UDP, and Unix hand-off in 0.4; IOCP, named pipes, and Windows hand-off in 0.5; io_uring after 1.0 (D-015).

## Server lifecycle

| Case | Tests (0.3) |
|---|---|
| 106, 107. Door calls idempotent | `edge::edge_106_107_door_calls_are_idempotent` |
| 108. Drain with nothing open | `edge::edge_108_drain_with_nothing_open_returns_at_once` |
| 109. Drain deadline already passed | `edge::edge_109_drain_deadline_in_the_past_kills_at_once` |
| 110. `request_stop` from a session | `edge::edge_110_request_stop_from_a_session_is_safe`, `server::test_request_stop_ends_wait_for_stop` |
| 111. `adopt` while draining | 0.4 (`Server::adopt` ships then) |
| 112. `release_listeners` with the door open | 0.4 (hand-off ships then) |
| 113. `kill` with a foreign or closed id | `edge::edge_113_kill_with_a_foreign_or_closed_id_is_false` |
| 114. Control line changes within one iteration | `src/control.rs::test_view_sees_only_final_state` |
| 115. `Draining` without a deadline | `edge::edge_115_draining_without_a_deadline_uses_the_drain_timeout` |
| 116. More workers than CPUs | `edge::edge_116_more_workers_than_cpus` |
| 117. `post` after shutdown | `edge::edge_117_post_after_shutdown_is_server_stopped` |
| 118. Session panic contained | `server::test_session_panic_is_contained`, `close_reasons::reason_session_panicked` |

## Configuration

| Case | Tests (0.3) |
|---|---|
| 119, 120. Zero values; per-listener above global | `edge::edge_119_120_bad_caps_fail_at_build`, `src/limits.rs::test_zero_values_rejected` |
| 121. Caps above `RLIMIT_NOFILE` | `src/limits.rs::test_validate_descriptor_limit_and_budget` |
| 122, 123. PROXY configuration | 0.4 |
| 124, 125. CIDR host bits; prefix too long | `src/addr.rs::test_cidr_parse_rejects_bad_text`, `src/addr.rs::test_cidr_new_masked_clears_bits`, `src/addr.rs::prop_cidr_and_prefix_key_match_integer_masks` |
| 126. Address in use | `edge::edge_126_address_in_use`, `src/tcp.rs::test_bind_in_use_maps_to_addr_in_use` |
| 127. Low port without privileges | `edge::edge_127_low_port_without_privileges`, `src/tcp.rs::test_bind_errors_map_by_class` |
| 128. IPv6 address with IPv6 disabled | `src/tcp.rs::test_bind_errors_map_by_class` |

## Cross-thread

| Case | Tests (0.3) |
|---|---|
| 129. Kill from 64 threads | `edge::edge_129_kill_from_many_threads_closes_once`, `src/sys/kill.rs::test_kill_from_many_threads_exactly_one_wins` |
| 130. Kill racing a close | `src/sys/kill.rs::loom_kill_never_acts_after_close`, `interleave::prop_every_connection_closes_exactly_once` |
| 131. Post racing a close: never delivered elsewhere | `edge::edge_10_bytes_sent_while_parked_are_read_after_the_wake` (post after close is `WrongWorker`), `src/completer.rs::loom_ring_two_producers_one_consumer` |
| 132. `stats()` while workers run | `edge::edge_132_stats_while_workers_run` (D-069) |

## Every close reason

`tests/close_reasons.rs` produces each close reason the blocking driver has in 0.3 on a real socket and asserts exactly one `Closed` event with it; `tests/interleave.rs` checks the exactly-once rule over random interleavings of FIN, RST, kill, timeouts, and a drain. `Io` comes from `shim::test_keepalive_timeout_is_an_io_error_not_a_deadline`. `HandshakeTimeout`, `ProxyUntrusted`, `ProxyMissing`, `ProxyInvalid`, `TlsFailed`, and `HelloRefused` arrive with PROXY and TLS in 0.4.
