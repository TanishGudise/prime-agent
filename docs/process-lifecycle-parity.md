# Process-lifecycle parity (TS vs Rust)

`scripts/process_lifecycle_parity.py` is a local differential tool: it runs the same daemon-socket steps
against two or more `prime-agent` binaries and compares what happens to user shell commands (`!cmd`,
`execute_bash`, `execute_bash_and_wait`), their processes, and the supervisor on signals. It uses real
binaries, an isolated HOME per run, a fixture provider whose base URL is unreachable, and no inference.
It is named outside `scripts/review_*_parity.py` on purpose, so CI's lifecycle step does not pick it up:
the regressions it found are guarded by Rust tests in the fixes, and the TS release is a reference to
compare against, not a spec.

## Running it

```bash
python3 scripts/process_lifecycle_parity.py \
  --binary ts=/path/to/prime-agent-0.9.8/prime-agent \
  --binary rust=target/debug/prime-agent \
  --check --receipt receipt.json
```

- The first `--binary` is the reference; every other binary is diffed against it.
- Without `--binary`, the script uses `ts=$PA_TS_BINARY rust=$PA_RUST_BINARY`.
- `--scenario NAME` (repeatable) limits the run; `--repeat N` repeats the variants of
  `fast_output_slow_reader`.
- `--check` asserts the reference (TS) behaviour listed below on every binary and exits 1 on any failure.
- Network: on macOS each binary runs under `sandbox-exec` with outbound IP denied (unix sockets work), so
  no binary can bootstrap its kernel venv or reach a provider. Elsewhere, run the script in a network-less
  container or namespace (for example `docker run --network none`).
- Process deaths are observed from kernel exit events (kqueue on macOS, pidfd on Linux); a timeout only
  bounds the "it survived" outcome. "Survived" means still alive 10 s after the step.

## Scenarios and checks

| Scenario | Observes | `--check` (TS behaviour) |
|---|---|---|
| `death_by_signal_exit_code` | exit code when the command's shell dies by SIGTERM/SIGKILL/SIGINT/SIGSEGV, a lone signal-killed command, a child killed inside a compound line | 128 + signal |
| `kill_or_replace_mid_command` | session `kill` / `new_session` while a forked command runs: `bash_end`, the command's shell and child | `kill` cancels the run and kills the child |
| `sighup_supervisor` | SIGHUP and SIGTERM to the supervisor: exit status, which processes survive, `daemon_closing` | SIGHUP is handled (exit status, not a signal death) |
| `supervisor_sigint_and_double_sigterm` | SIGINT, and SIGTERM twice in a row | none (observed) |
| `client_disconnect_mid_command` | the attached client leaves while a command waits; a second client attaches | none (observed) |
| `await_past_client_timeout` | a client gives up on a pending `execute_bash_and_wait` | none (observed) |
| `background_command_slot` | `cmd &`: the run settles, the slot frees, the background process lives on | none (observed) |
| `graceful_shutdown_forked` | the `shutdown` command while a forked command runs | none (observed) |
| `orphaned_worker_mid_command` | SIGKILL to the supervisor while a command runs (2 s lost-exit window) | none (observed) |
| `overlapping_runs_abort` | one `abort_bash` against a streamed run and a concurrent `execute_bash_and_wait` | none (observed) |
| `abort_edge_cases` | abort with nothing running, right behind `execute_bash`, twice; a fresh command afterwards | none (observed) |
| `abort_right_behind_execute` | `execute_bash` + `abort_bash` in one write, 20 times | the abort cancels the run every time |
| `output_interleaving` | stdout/stderr order over 20 runs | none (observed) |
| `split_utf8_and_ansi` | multi-byte characters and ANSI sequences that straddle pipe reads (stream, spill, stored row) | no U+FFFD; no ANSI fragment in the stored row |
| `command_reads_stdin` | a command reading stdin | none (observed) |
| `sigkill_worker` | SIGKILL to the session's worker, idle and mid-command: recovery, the old command's processes | the dead worker's command is reaped |
| `fast_output_slow_reader` | 10 MiB of output with a reading and a non-reading client: live bytes, `bash_end`, the stored row, the spill | none (observed) |
| `live_stream_memory` | supervisor + worker RSS after 50/200 MiB of output to a client that never reads | none (observed) |
| `tui_quit_mid_command` | quitting the real TUI while a `!` command runs | none (observed) |

Observed-only scenarios still report every difference against the reference in the receipt; checks exist
for the differences that are regressions.

## Reference, not spec

Every check encodes the TS v0.9.8 behaviour for a difference that was judged a regression. Where Rust
differs on purpose (the drain stopping workers, its exit 0, no replacement supervisor) or improves on TS,
the receipt still shows the difference, and nothing asserts it.
