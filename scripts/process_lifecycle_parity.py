#!/usr/bin/env python3
"""Real-binary process-lifecycle parity: user shell commands, signals and pipes, TS vs Rust.

Each scenario runs the same daemon-socket steps against every binary under test and records an
observation (events, exit codes, which processes outlived the step, persisted rows). No inference,
ambient state or production daemon is used: each run gets an isolated HOME, a fixture provider whose
base URL is unreachable, and an outbound-network-denying sandbox (unix sockets stay allowed), so no
binary can bootstrap or phone home. Process deaths are observed with kqueue NOTE_EXIT events; a
timeout only bounds the "it survived" outcome.

Usage:
  process_lifecycle_parity.py --binary ts=/path/prime-agent --binary rust=/path/prime-agent \
      [--scenario NAME ...] [--receipt out.json]
The first --binary is the reference the others are compared against.
"""
import argparse
import json
import os
import re
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

# macOS: deny outbound IP (unix sockets stay allowed) so no binary can bootstrap or phone home.
# Elsewhere run the suite in a network-less container or namespace (e.g. `docker run --network none`).
SANDBOX = (["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network-outbound (remote ip))"]
           if os.path.exists("/usr/bin/sandbox-exec") else [])
READY_LIMIT = 30
EVENT_LIMIT = 15
SURVIVE_LIMIT = 10
STOP_LIMIT = 60
FORKED = (
    "sh -c 'echo \"ready $PPID $$\"; exec sleep 300'; echo after"
)


def env_for(root):
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    for name in ("home", "tmp", "xdg", "agent/sessions", "work"):
        (root / name).mkdir(parents=True, exist_ok=True)
    env.update(HOME=str(root / "home"), TMPDIR=str(root / "tmp"), XDG_CONFIG_HOME=str(root / "xdg"),
               PRIME_AGENT_CODING_AGENT_DIR=str(root / "agent"), PI_CODING_AGENT_DIR=str(root / "agent"),
               TERM="xterm-256color", PRIME_AGENT_MODEL_PROVIDER="parity-local",
               PRIME_AGENT_MODEL="parity-1", PI_OFFLINE="1", DO_NOT_TRACK="1")
    (root / "agent/settings.json").write_text(json.dumps({
        "onboardingCompleted": True, "onboardingShown": True, "telemetry": {"noticeShown": True}}))
    (root / "agent/models.json").write_text(json.dumps({"providers": {
        "parity-local": {"api": "openai-completions", "baseUrl": "http://127.0.0.1:1/v1",
                         "apiKey": "fixture-only", "models": [{"id": "parity-1", "name": "Parity 1",
                         "contextWindow": 128000, "maxTokens": 4096}]}}}))
    return env


def wait_exit(pids, limit):
    """Pid -> exited within `limit`, from kernel exit events (kqueue NOTE_EXIT on macOS, pidfd on
    Linux); an already-gone pid counts as exited."""
    if not hasattr(select, "kqueue"):
        return wait_exit_pidfd(pids, limit)
    kq = select.kqueue()
    pending = set()
    for pid in pids:
        try:
            kq.control([select.kevent(pid, select.KQ_FILTER_PROC,
                                      select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0)
            pending.add(pid)
        except (ProcessLookupError, OSError):
            pass
    deadline = time.monotonic() + limit
    while pending:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        for event in kq.control(None, len(pending), left):
            pending.discard(event.ident)
    kq.close()
    return {pid: pid not in pending for pid in pids}


def wait_exit_pidfd(pids, limit):
    poller, fds = select.poll(), {}
    for pid in pids:
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            continue
        fds[fd] = pid
        poller.register(fd, select.POLLIN)
    deadline = time.monotonic() + limit
    pending = set(fds.values())
    while pending:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        for fd, _ in poller.poll(left * 1000):
            pending.discard(fds[fd])
            poller.unregister(fd)
    for fd in fds:
        os.close(fd)
    return {pid: pid not in pending for pid in pids}


def children_of(pid):
    out = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True).stdout
    return [int(p) for p, pp in (line.split() for line in out.splitlines()) if int(pp) == pid]


class Client:
    def __init__(self, path, protocol=None):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(str(path))
        self.buffer = b""
        self.frames = []
        self.next_id = 0
        self.hello = self.read(lambda frame: frame.get("type") == "daemon_hello", READY_LIMIT)
        self.protocol = protocol or self.hello.get("protocol")

    def pump(self, limit):
        self.sock.settimeout(limit)
        try:
            chunk = self.sock.recv(1 << 20)
        except socket.timeout:
            return
        if not chunk:
            # Like a real client, close our end once the daemon hangs up: the TS supervisor's
            # shutdown waits for its clients' sockets to close.
            self.sock.close()
            raise ConnectionError("daemon closed the connection")
        self.buffer += chunk
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            self.frames.append(json.loads(line))

    def read(self, predicate, limit):
        """The first unseen frame matching `predicate` (consumed), or None after `limit`."""
        deadline = time.monotonic() + limit
        while True:
            for index, frame in enumerate(self.frames):
                if predicate(frame):
                    return self.frames.pop(index)
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            self.pump(min(left, 0.5))

    def request(self, command, limit=EVENT_LIMIT):
        self.next_id += 1
        cid = f"req-{self.next_id}"
        self.sock.sendall((json.dumps({"type": "command", "id": cid, "protocol": self.protocol,
                                       "command": command}) + "\n").encode())
        return self.read(lambda frame: frame.get("id") == cid and frame.get("type") == "response", limit)

    def send_together(self, commands):
        """Write several command frames in one write (no wait between them); answers their ids."""
        ids, payload = [], b""
        for command in commands:
            self.next_id += 1
            cid = f"req-{self.next_id}"
            ids.append(cid)
            payload += (json.dumps({"type": "command", "id": cid, "protocol": self.protocol,
                                    "command": command}) + "\n").encode()
        self.sock.sendall(payload)
        return ids

    def response(self, cid, limit=EVENT_LIMIT):
        return self.read(lambda frame: frame.get("id") == cid and frame.get("type") == "response", limit)

    def event(self, event_type, limit=EVENT_LIMIT, predicate=lambda event: True):
        frame = self.read(lambda frame: frame.get("type") == "session_event"
                          and (frame.get("event") or {}).get("type") == event_type
                          and predicate(frame["event"]), limit)
        return frame["event"] if frame else None

    def drain_in_background(self):
        """Keep reading (and record frame types) until the daemon hangs up, then close."""
        seen = []

        def drain():
            try:
                while True:
                    self.pump(0.2)
                    while self.frames:
                        frame = self.frames.pop(0)
                        seen.append(frame.get("type"))
            except (ConnectionError, OSError):
                pass

        threading.Thread(target=drain, daemon=True).start()
        return seen

    def close(self):
        self.sock.close()


class Fixture:
    """One sandboxed daemon over an isolated root; tracks every pid it learns for cleanup."""

    def __init__(self, binary, extra_env=None):
        self.root = Path(tempfile.mkdtemp(prefix="pal-", dir="/tmp"))
        self.env = env_for(self.root)
        self.env.update(extra_env or {})
        self.socket = self.root / "d.sock"
        self.log = open(self.root / "daemon.log", "wb")
        self.daemon = subprocess.Popen(SANDBOX + [str(binary), "--mode", "daemon", "--daemon-socket",
                                       str(self.socket)], cwd=self.root, env=self.env, stdout=self.log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        self.pids = {self.daemon.pid}
        deadline = time.monotonic() + READY_LIMIT
        while not self.socket.exists():
            if self.daemon.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("daemon did not open its socket")
            threading.Event().wait(0.05)  # bounded socket-readiness poll, like the repo's harnesses
        self.client = Client(self.socket)

    def session(self):
        created = self.client.request({"type": "create", "config": {"cwd": str(self.root / "work")}},
                                      READY_LIMIT)
        if not created or not created.get("success"):
            raise RuntimeError(f"create failed: {created}")
        sid = created["data"]["activeSessionId"]
        attached = self.client.request({"type": "attach", "activeSessionId": sid, "clientId": "parity"})
        if not attached or not attached.get("success"):
            raise RuntimeError(f"attach failed: {attached}")
        self.pids.update(children_of(self.daemon.pid))
        return sid

    def workers(self):
        """The supervisor's worker processes (TS: `--mode daemon` on a worker-*.sock; Rust: `worker`)."""
        children = children_of(self.daemon.pid)
        self.pids.update(children)
        out = subprocess.run(["ps", "-o", "pid=,command=", "-p", ",".join(map(str, children)) or "0"],
                             capture_output=True, text=True).stdout
        return [int(line.split()[0]) for line in out.splitlines()
                if "worker" in line.split(None, 1)[1]] if children else []

    def start_forked(self, sid, client=None):
        """Run FORKED as a user command; answers (shell pid, child pid) once the child runs."""
        client = client or self.client
        response = client.request({"type": "execute_bash", "activeSessionId": sid, "command": FORKED})
        if not response or not response.get("success"):
            raise RuntimeError(f"execute_bash failed: {response}")
        ready = client.event("bash_output", READY_LIMIT, lambda event: "ready " in event.get("chunk", ""))
        if not ready:
            raise RuntimeError("the forked command never reported ready")
        shell, child = (int(value) for value in ready["chunk"].split("ready ", 1)[1].split()[:2])
        self.pids.update((shell, child))
        return shell, child

    def rooted_pids(self):
        out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
        return {int(line.split()[0]) for line in out.splitlines() if str(self.root) in line}

    def close(self):
        try:
            os.killpg(self.daemon.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        # A dying TS worker can still launch a replacement supervisor: kill, wait, rescan until quiet.
        for _ in range(5):
            self.pids |= self.rooted_pids()
            for pid in self.pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            wait_exit(sorted(self.pids), 5)
            if not self.rooted_pids():
                break
        try:
            self.daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self.log.close()
        shutil.rmtree(self.root, ignore_errors=True)


def bucket(seconds):
    for limit in (1, 5, 15, 60):
        if seconds < limit:
            return f"<{limit}s"
    return f">={STOP_LIMIT}s"


def exit_kind(process):
    code = process.returncode
    if code is None:
        return "running"
    return f"signal {-code}" if code < 0 else f"exit {code}"


# --------------------------------------------------------------------------- scenarios

def sighup_supervisor(binary):
    """SIGHUP (and SIGTERM as the control) to the supervisor while a forked user command runs."""
    return signal_supervisor(binary, {"SIGHUP": [signal.SIGHUP], "SIGTERM": [signal.SIGTERM]})


def supervisor_sigint_and_double_sigterm(binary):
    """SIGINT, and SIGTERM sent twice back to back, to the supervisor while a forked command runs."""
    return signal_supervisor(binary, {"SIGINT": [signal.SIGINT],
                                      "SIGTERM_twice": [signal.SIGTERM, signal.SIGTERM]})


def signal_supervisor(binary, cases):
    observed = {}
    for name, signals in cases.items():
        run = Fixture(binary)
        try:
            sid = run.session()
            shell, child = run.start_forked(sid)
            workers = run.workers()
            frames = run.client.drain_in_background()
            started = time.monotonic()
            for signum in signals:
                run.daemon.send_signal(signum)
            exited = wait_exit([run.daemon.pid], STOP_LIMIT)[run.daemon.pid]
            took = bucket(time.monotonic() - started) if exited else None
            run.daemon.wait(timeout=5) if exited else run.daemon.poll()
            after = wait_exit(workers + [shell, child], SURVIVE_LIMIT)
            observed[name] = {
                "supervisor_exited": exited, "supervisor_exit": exit_kind(run.daemon),
                "supervisor_exit_within": took,
                "client_saw_daemon_closing": "daemon_closing" in frames,
                "socket_file_left": run.socket.exists(),
                "worker_survived": any(not after[pid] for pid in workers),
                "shell_survived": not after[shell], "child_survived": not after[child],
            }
        finally:
            run.close()
    return observed


def kill_or_replace_mid_command(binary):
    """Session `kill` and a `new_session` replacement while a forked user command runs."""
    observed = {}
    for name in ("kill", "new_session"):
        run = Fixture(binary)
        try:
            sid = run.session()
            shell, child = run.start_forked(sid)
            response = run.client.request({"type": name, "activeSessionId": sid}, READY_LIMIT)
            end = run.client.event("bash_end", SURVIVE_LIMIT)
            after = wait_exit([shell, child], SURVIVE_LIMIT)
            observed[name] = {
                "response_success": bool(response and response.get("success")),
                "bash_end": {key: end.get(key) for key in ("exitCode", "cancelled")} if end else None,
                "shell_survived": not after[shell], "child_survived": not after[child],
            }
        finally:
            run.close()
    return observed


def client_disconnect_mid_command(binary):
    """The attached client disconnects while a user command waits on a gate; a second client
    attaches, the gate opens, and the run's outcome is observed."""
    run = Fixture(binary)
    try:
        sid = run.session()
        gate = run.root / "work" / "gate.fifo"
        os.mkfifo(gate)
        response = run.client.request({"type": "execute_bash", "activeSessionId": sid,
                                       "command": 'echo "ready $$"; read line < gate.fifo; echo "got $line"'})
        ready = run.client.event("bash_output", READY_LIMIT, lambda event: "ready " in event.get("chunk", ""))
        shell = int(ready["chunk"].split("ready ", 1)[1].split()[0])
        run.pids.add(shell)
        run.client.close()
        aborted = wait_exit([shell], 3)[shell]
        second = Client(run.socket, run.client.protocol)
        attached = second.request({"type": "attach", "activeSessionId": sid, "clientId": "parity-2"})
        state = second.request({"type": "get_connection_state", "activeSessionId": sid})
        writer = os.open(gate, os.O_WRONLY | os.O_NONBLOCK) if not aborted else None
        if writer is not None:
            os.write(writer, b"go\n")
            os.close(writer)
        end = second.event("bash_end", EVENT_LIMIT)
        messages = second.request({"type": "get_messages", "activeSessionId": sid})
        rows = [message for message in ((messages or {}).get("data") or {}).get("messages", [])
                if message.get("role") == "bashExecution"]
        second.close()
        return {
            "execute_bash_success": bool(response and response.get("success")),
            "aborted_on_disconnect": aborted,
            "reattach_success": bool(attached and attached.get("success")),
            "bash_running_after_reattach": ((state or {}).get("data") or {}).get("isBashRunning"),
            "bash_end": {key: end.get(key) for key in ("exitCode", "cancelled")} if end else None,
            "rows": [{key: row.get(key) for key in ("output", "exitCode", "cancelled")} for row in rows],
        }
    finally:
        run.close()


def death_by_signal_exit_code(binary):
    """Exit-code mapping for commands that die by signal, through execute_bash_and_wait."""
    run = Fixture(binary)
    try:
        sid = run.session()
        observed = {}
        for name, command in (("self_SIGTERM", "kill -TERM $$"), ("self_SIGKILL", "kill -KILL $$"),
                              ("self_SIGSEGV", "kill -SEGV $$"),
                              ("compound_child_SIGKILL", "cd . && sh -c 'kill -KILL $$'"),
                              ("single_command_SIGSEGV", "sh -c 'kill -SEGV $$'"),
                              ("self_SIGINT", "kill -INT $$"), ("child_SIGTERM_then_exit0",
                               "sh -c 'kill -TERM $$'; echo after"), ("exit_130", "exit 130")):
            response = run.client.request({"type": "execute_bash_and_wait", "activeSessionId": sid,
                                           "command": command}, READY_LIMIT)
            data = (response or {}).get("data") or {}
            observed[name] = {"success": bool(response and response.get("success")),
                              "exitCode": data.get("exitCode"), "cancelled": data.get("cancelled"),
                              "output": data.get("output")}
        return observed
    finally:
        run.close()


REPEAT = 1


def fast_output_slow_reader(binary):
    """10 MiB of output: with/without a short first line, with a client that stops reading and one
    that keeps reading, REPEAT runs each. Per run: the stored row's length, truncation flag, hash and
    spill status, and the live bytes the client received."""
    observed = {}
    for first_line in ("ready_line", "no_ready_line"):
        for mode in ("non_reading_client", "reading_client"):
            runs = [fast_output(binary, reading=(mode == "reading_client"), ready_line=(first_line == "ready_line"))
                    for _ in range(REPEAT)]
            observed[f"{first_line}/{mode}"] = {
                "row_lengths": sorted({run["row"]["output_chars"] for run in runs}),
                "short_rows": sum(run["row"]["output_chars"] < 1000 for run in runs),
                "runs": runs,
            }
    return observed


def spill_tail(path):
    """The last bytes of a spill file (stripped), or b"" if it vanished mid-probe."""
    try:
        with open(path, "rb") as stream:
            stream.seek(max(0, path.stat().st_size - 64))
            return stream.read().rstrip()
    except OSError:
        return b""


def fast_output(binary, reading, ready_line):
    run = Fixture(binary)
    try:
        sid = run.session()
        size = 10 * 1024 * 1024
        prefix = 'echo "ready $$"; ' if ready_line else ""
        command = f"{prefix}yes 0123456789abcdef | head -c {size}; echo; echo end-marker"
        run.client.request({"type": "execute_bash", "activeSessionId": sid, "command": command})
        start = run.client.event("bash_start", READY_LIMIT)
        finished_unread = None
        if not reading:
            # Stop reading once the run started: the command must still finish while the client is
            # not draining its socket (the spill file's end marker is the completion signal).
            deadline = time.monotonic() + 30
            spill_done = False
            while time.monotonic() < deadline and not spill_done:
                spill_done = any(spill_tail(path).endswith(b"end-marker")
                                 for pattern in ("pa-bash-*.log", "pi-bash-*.log")
                                 for path in (run.root / "tmp").rglob(pattern))
                if not spill_done:
                    threading.Event().wait(0.2)  # bounded file-state probe while the client stays silent
            finished_unread = spill_done
        streamed = 0
        chunks = 0
        end = None
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and end is None:
            frame = run.client.read(lambda f: f.get("type") == "session_event"
                                    and (f.get("event") or {}).get("type") in ("bash_output", "bash_end"), 5)
            if frame is None:
                break
            event = frame["event"]
            if event["type"] == "bash_end":
                end = event
            else:
                streamed += len(event.get("chunk", "").encode())
                chunks += 1
        messages = run.client.request({"type": "get_messages", "activeSessionId": sid})
        rows = [message for message in ((messages or {}).get("data") or {}).get("messages", [])
                if message.get("role") == "bashExecution"]
        row = rows[-1] if rows else {}
        spill = Path(end["fullOutputPath"]) if end and end.get("fullOutputPath") else None
        spill_text = spill.read_bytes() if spill and spill.exists() else b""
        return {
            "shell_finished_while_client_not_reading": finished_unread,
            "streamed_bytes": streamed,
            "bash_end": {key: end.get(key) for key in ("exitCode", "cancelled", "truncated")} if end else None,
            "streamed_bytes_at_least_size": streamed >= size,

            # No bash_end or no fullOutputPath: unknown, not false.
            "spill_bytes_at_least_size": len(spill_text) >= size if spill else None,
            "spill_ends_with_marker": spill_text.rstrip().endswith(b"end-marker") if spill else None,
            "full_output_path_present": bool(end and end.get("fullOutputPath")),
            "row": {"output_chars": len(row.get("output", "")),
                    "output_sha256_12": __import__("hashlib").sha256(row.get("output", "").encode()).hexdigest()[:12],
                    "truncated": row.get("truncated"),
                    "full_output_path_present": bool(row.get("fullOutputPath")),
                    "output_ends_with_marker": row.get("output", "").rstrip().endswith("end-marker")},
        }
    finally:
        run.close()


def pid_channel(run, name):
    """A FIFO the command writes its pid to; answers a function that waits (bounded) for the pid."""
    fifo = run.root / "work" / name
    os.mkfifo(fifo)
    box = {}

    def read():
        with open(fifo) as stream:  # blocks until the command opens the write end
            box["pid"] = int(stream.read().split()[0])

    thread = threading.Thread(target=read, daemon=True)
    thread.start()

    def wait(limit=READY_LIMIT):
        thread.join(limit)
        pid = box.get("pid")
        if pid:
            run.pids.add(pid)
        return pid
    return wait


def open_gate(path):
    writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK)  # the command is blocked reading it
    os.write(writer, b"go\n")
    os.close(writer)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def background_command_slot(binary):
    """`cmd &`: the run settles when the shell exits; the slot frees; the background process lives on."""
    run = Fixture(binary)
    try:
        sid = run.session()
        run.client.request({"type": "execute_bash", "activeSessionId": sid,
                            "command": "sleep 300 & echo $! > bg.pid; echo started"})
        end = run.client.event("bash_end", SURVIVE_LIMIT)
        pid_file = run.root / "work" / "bg.pid"
        background = int(pid_file.read_text().split()[0]) if pid_file.exists() else None
        if background:
            run.pids.add(background)
        second = run.client.request({"type": "execute_bash", "activeSessionId": sid, "command": "echo second"})
        second_end = run.client.event("bash_end", EVENT_LIMIT) if second and second.get("success") else None
        return {
            "bash_end_within_10s": {key: end.get(key) for key in ("exitCode", "cancelled")} if end else None,
            "second_command": "ran" if second_end else (second or {}).get("error"),
            "background_process_alive": alive(background) if background else None,
        }
    finally:
        run.close()


def graceful_shutdown_forked(binary):
    """The daemon's `shutdown` command while a forked user command runs."""
    run = Fixture(binary)
    try:
        sid = run.session()
        shell, child = run.start_forked(sid)
        workers = run.workers()
        frames = run.client.drain_in_background()
        started = time.monotonic()
        control = Client(run.socket, run.client.protocol)
        response = control.request({"type": "shutdown"}, READY_LIMIT)
        control.drain_in_background()
        exited = wait_exit([run.daemon.pid], STOP_LIMIT)[run.daemon.pid]
        took = bucket(time.monotonic() - started) if exited else None
        if exited:
            run.daemon.wait(timeout=5)
        after = wait_exit(workers + [shell, child], SURVIVE_LIMIT)
        return {
            "response_success": bool(response and response.get("success")),
            "supervisor_exit": exit_kind(run.daemon), "supervisor_exit_within": took,
            "worker_survived": any(not after[pid] for pid in workers),
            "shell_survived": not after[shell], "child_survived": not after[child],
            "client_saw_daemon_closing": "daemon_closing" in frames,
        }
    finally:
        run.close()


def orphaned_worker_mid_command(binary):
    """SIGKILL the supervisor while a gated user command runs (2 s lost-exit window)."""
    run = Fixture(binary, {"PRIME_AGENT_INTERNAL_WORKER_SUPERVISOR_LOST_EXIT_MS": "2000"})
    try:
        sid = run.session()
        gate = run.root / "work" / "gate.fifo"
        os.mkfifo(gate)
        run.client.request({"type": "execute_bash", "activeSessionId": sid,
                            "command": 'echo "ready $$"; read line < gate.fifo; echo "got $line"'})
        ready = run.client.event("bash_output", READY_LIMIT, lambda event: "ready " in event.get("chunk", ""))
        shell = int(ready["chunk"].split("ready ", 1)[1].split()[0])
        run.pids.add(shell)
        workers = run.workers()
        before = run.rooted_pids()
        run.daemon.send_signal(signal.SIGKILL)
        run.daemon.wait(timeout=10)
        during = wait_exit(workers + [shell], SURVIVE_LIMIT)
        replacement = sorted(pid for pid in run.rooted_pids() - before
                             if pid not in workers and pid != shell)
        worker_alive_during = any(not during[pid] for pid in workers)
        if not during[shell]:
            open_gate(gate)
        shell_done = wait_exit([shell], EVENT_LIMIT)[shell]
        worker_exit_after = wait_exit(workers, 45)
        return {
            "worker_alive_10s_after_supervisor_death": worker_alive_during,
            "command_alive_10s_after_supervisor_death": not during[shell],
            "command_finished_after_gate": shell_done,
            "worker_exited_within_45s_after_command": all(worker_exit_after.values()),
            "replacement_supervisor_started": bool(replacement),
        }
    finally:
        run.close()


def overlapping_runs_abort(binary):
    """A streamed execute_bash and a concurrent execute_bash_and_wait, then one abort_bash."""
    run = Fixture(binary)
    try:
        sid = run.session()
        shell_a, child_a = run.start_forked(sid)
        second = Client(run.socket, run.client.protocol)
        second.request({"type": "attach", "activeSessionId": sid, "clientId": "parity-2"})
        wait_b = pid_channel(run, "b.fifo")
        box = {}

        def awaited():
            box["response"] = second.request({"type": "execute_bash_and_wait", "activeSessionId": sid,
                                              "command": "sh -c 'echo $$ > b.fifo; exec sleep 300'"}, 40)
        thread = threading.Thread(target=awaited, daemon=True)
        thread.start()
        child_b = wait_b()
        aborted = run.client.request({"type": "abort_bash", "activeSessionId": sid})
        end_a = run.client.event("bash_end", EVENT_LIMIT)
        thread.join(30)
        data_b = ((box.get("response") or {}).get("data")) or {}
        after = wait_exit([child_a, child_b] if child_b else [child_a], SURVIVE_LIMIT)
        second.close()
        return {
            "awaited_started": bool(child_b),
            "abort_success": bool(aborted and aborted.get("success")),
            "streamed_bash_end": {key: end_a.get(key) for key in ("exitCode", "cancelled")} if end_a else None,
            "awaited_response": {key: data_b.get(key) for key in ("exitCode", "cancelled")}
                                if box.get("response") else None,
            "streamed_child_survived": not after[child_a],
            "awaited_child_survived": (not after[child_b]) if child_b else None,
        }
    finally:
        run.close()


def abort_edge_cases(binary):
    """abort_bash with nothing running, right behind execute_bash, twice; then a fresh command."""
    run = Fixture(binary)
    try:
        sid = run.session()
        idle = run.client.request({"type": "abort_bash", "activeSessionId": sid})
        stray = run.client.event("bash_end", 2)
        ids = run.client.send_together([
            {"type": "execute_bash", "activeSessionId": sid, "command": "touch ran.marker; sleep 300"},
            {"type": "abort_bash", "activeSessionId": sid}])
        responses = [run.client.response(cid) for cid in ids]
        early_end = run.client.event("bash_end", EVENT_LIMIT)
        marker = (run.root / "work" / "ran.marker").exists()
        busy = ((run.client.request({"type": "get_connection_state", "activeSessionId": sid}) or {})
                .get("data") or {}).get("isBashRunning")
        if early_end is None:  # the run kept going: clear it so the rest of the scenario can run
            run.client.request({"type": "abort_bash", "activeSessionId": sid})
            run.client.event("bash_end", EVENT_LIMIT)
        shell, child = run.start_forked(sid)
        double = [run.client.request({"type": "abort_bash", "activeSessionId": sid}) for _ in range(2)]
        double_end = run.client.event("bash_end", EVENT_LIMIT)
        extra_end = run.client.event("bash_end", 2)
        after = wait_exit([child], SURVIVE_LIMIT)
        fresh = run.client.request({"type": "execute_bash_and_wait", "activeSessionId": sid, "command": "echo ok"})
        fresh_data = (fresh or {}).get("data") or {}
        return {
            "idle_abort_success": bool(idle and idle.get("success")),
            "idle_abort_emitted_bash_end": stray is not None,
            "abort_right_behind_execute": {
                "responses_success": [bool(r and r.get("success")) for r in responses],
                "bash_end": {key: early_end.get(key) for key in ("exitCode", "cancelled")} if early_end else None,
                "command_ran": marker, "slot_busy_after": busy,
            },
            "double_abort": {
                "responses_success": [bool(r and r.get("success")) for r in double],
                "bash_end": {key: double_end.get(key) for key in ("exitCode", "cancelled")} if double_end else None,
                "second_bash_end": extra_end is not None,
                "child_survived": not after[child],
            },
            "fresh_command_after_aborts": {key: fresh_data.get(key) for key in ("output", "exitCode", "cancelled")},
        }
    finally:
        run.close()


def output_interleaving(binary):
    """stdout/stderr order in the returned output over 20 runs of the same command."""
    run = Fixture(binary)
    try:
        sid = run.session()
        orders = {}
        for _ in range(20):
            response = run.client.request({"type": "execute_bash_and_wait", "activeSessionId": sid,
                                           "command": "echo o1; echo e1 >&2; echo o2; echo e2 >&2"})
            key = ((response or {}).get("data") or {}).get("output", "").replace("\n", " ").strip()
            orders[key] = orders.get(key, 0) + 1
        return {"orders": orders, "always_written_order": orders == {"o1 e1 o2 e2": 20}}
    finally:
        run.close()


def split_utf8_and_ansi(binary):
    """Multi-byte characters and ANSI sequences that straddle read-chunk boundaries."""
    run = Fixture(binary)
    try:
        sid = run.session()
        observed = {}
        for name, command, expect_line in (
                ("utf8_euro", "yes '€€' | head -c 3000000; echo", "€€"),
                ("ansi_red_x", "yes $'\\e[31mX\\e[0m' | head -c 2000000; echo", "X")):
            run.client.request({"type": "execute_bash", "activeSessionId": sid, "command": command})
            streamed, end = [], None
            while end is None:
                frame = run.client.read(lambda f: f.get("type") == "session_event"
                                        and (f.get("event") or {}).get("type") in ("bash_output", "bash_end"), 30)
                if frame is None:
                    break
                if frame["event"]["type"] == "bash_end":
                    end = frame["event"]
                else:
                    streamed.append(frame["event"].get("chunk", ""))
            messages = run.client.request({"type": "get_messages", "activeSessionId": sid})
            rows = [m for m in ((messages or {}).get("data") or {}).get("messages", [])
                    if m.get("role") == "bashExecution"]
            row = rows[-1].get("output", "") if rows else ""
            spill = Path(end["fullOutputPath"]) if end and end.get("fullOutputPath") else None
            spill_text = spill.read_text(errors="strict") if spill and spill.exists() else ""

            def bad_lines(text):
                lines = [line for line in text.split("\n")[1:-2]]  # drop the edge lines of a tail window
                return sum(line != expect_line for line in lines)
            stream_text = "".join(streamed)
            observed[name] = {
                "replacement_chars": {"stream": stream_text.count("\ufffd"), "row": row.count("\ufffd"),
                                      "spill": spill_text.count("\ufffd")},
                "corrupted_lines": {"stream": bad_lines(stream_text), "row": bad_lines(row),
                                    "spill": bad_lines(spill_text)},
                "row_samples": sorted({line for line in row.split("\n")[1:-2] if line != expect_line})[:3],
            }
        return observed
    finally:
        run.close()


def command_reads_stdin(binary):
    """A user command reading stdin sees EOF immediately."""
    run = Fixture(binary)
    try:
        sid = run.session()
        response = run.client.request({"type": "execute_bash_and_wait", "activeSessionId": sid,
                                       "command": 'cat; echo "cat=$?"; read x; echo "read=$? [$x]"'}, READY_LIMIT)
        data = (response or {}).get("data") or {}
        return {key: data.get(key) for key in ("output", "exitCode", "cancelled")}
    finally:
        run.close()


def sigkill_worker(binary):
    """SIGKILL the session's worker (idle, then with a forked command running)."""
    observed = {}
    for name in ("idle", "running_command"):
        run = Fixture(binary)
        try:
            sid = run.session()
            shell = child = None
            if name == "running_command":
                shell, child = run.start_forked(sid)
            workers = run.workers()
            for pid in workers:
                os.kill(pid, signal.SIGKILL)
            wait_exit(workers, EVENT_LIMIT)
            started = time.monotonic()
            probe = Client(run.socket, run.client.protocol)
            # A client attaching is what wakes recovery (TS parks a crashed worker until then).
            probe.request({"type": "attach", "activeSessionId": sid, "clientId": "parity-probe"}, STOP_LIMIT)
            # Retry (bounded) until the session runs a command again; record the first answer too.
            first = probe.request({"type": "get_connection_state", "activeSessionId": sid}, STOP_LIMIT)
            state, command = first, None
            while time.monotonic() - started < STOP_LIMIT:
                command = probe.request({"type": "execute_bash_and_wait", "activeSessionId": sid,
                                         "command": "echo after-restart"}, STOP_LIMIT)
                if command and command.get("success"):
                    break
                threading.Event().wait(1)  # bounded retry while the worker recovers
            took = bucket(time.monotonic() - started) if command and command.get("success") else None
            new_workers = [pid for pid in run.workers() if pid not in workers]
            after = wait_exit([shell, child], SURVIVE_LIMIT) if shell else {}
            probe.close()
            observed[name] = {
                "first_probe_success": bool(state and state.get("success")),
                "usable_again_within": took,
                "new_worker": bool(new_workers),
                "command_after_restart": (((command or {}).get("data") or {}).get("output")
                                          if command and command.get("success") else (command or {}).get("error")),
                "old_command_shell_survived": (not after[shell]) if shell else None,
                "old_command_child_survived": (not after[child]) if child else None,
            }
        finally:
            run.close()
    return observed


def await_past_client_timeout(binary):
    """A client gives up on a pending execute_bash_and_wait (closes); the run's fate afterwards."""
    run = Fixture(binary)
    try:
        sid = run.session()
        gate = run.root / "work" / "gate.fifo"
        os.mkfifo(gate)
        impatient = Client(run.socket, run.client.protocol)
        impatient.request({"type": "attach", "activeSessionId": sid, "clientId": "impatient"})
        wait_shell = pid_channel(run, "s.fifo")
        impatient.next_id += 1
        impatient.sock.sendall((json.dumps({"type": "command", "id": "awaited", "protocol": impatient.protocol,
            "command": {"type": "execute_bash_and_wait", "activeSessionId": sid,
                        "command": 'echo $$ > s.fifo; read line < gate.fifo; echo "got $line"'}}) + "\n").encode())
        shell = wait_shell()
        impatient.close()
        aborted = wait_exit([shell], 3)[shell]
        state = run.client.request({"type": "get_connection_state", "activeSessionId": sid})
        if not aborted:
            open_gate(gate)
        finished = wait_exit([shell], EVENT_LIMIT)[shell]
        later = run.client.request({"type": "get_connection_state", "activeSessionId": sid})
        messages = run.client.request({"type": "get_messages", "activeSessionId": sid})
        rows = [m for m in ((messages or {}).get("data") or {}).get("messages", [])
                if m.get("role") == "bashExecution"]
        return {
            "aborted_when_client_left": aborted,
            "bash_running_while_pending": ((state or {}).get("data") or {}).get("isBashRunning"),
            "finished_after_gate": finished,
            "bash_running_after": ((later or {}).get("data") or {}).get("isBashRunning"),
            "rows": [{key: row.get(key) for key in ("output", "exitCode", "cancelled")} for row in rows],
        }
    finally:
        run.close()


def live_stream_memory(binary):
    """Supervisor and worker RSS after N MiB of output with a client that never reads."""
    observed = {}
    for mib in (50, 200):
        run = Fixture(binary)
        try:
            sid = run.session()
            workers = run.workers()
            wait_shell = pid_channel(run, "m.fifo")

            def rss():
                pids = [run.daemon.pid] + workers
                out = subprocess.run(["ps", "-o", "rss=", "-p", ",".join(map(str, pids))],
                                     capture_output=True, text=True).stdout.split()
                return round(sum(int(value) for value in out) / 1024)
            baseline = rss()
            run.client.request({"type": "execute_bash", "activeSessionId": sid,
                                "command": f"echo $$ > m.fifo; yes 0123456789abcdef | head -c {mib * 1024 * 1024}"})
            shell = wait_shell()
            finished = wait_exit([shell], 120)[shell] if shell else False
            observed[f"{mib}MiB"] = {"command_finished_unread": finished,
                                     "rss_growth_mib": rss() - baseline}
        finally:
            run.close()
    return observed


def tui_quit_mid_command(binary):
    """Quit the real TUI (Ctrl+D, then Ctrl+C twice if still running) while a `!` command runs."""
    import pty
    run = Fixture(binary)
    try:
        wait_child = pid_channel(run, "c.fifo")
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(run.root / "work")
            argv = SANDBOX + [str(binary), "--daemon-socket", str(run.socket)]
            os.execve(argv[0], argv, run.env)
        run.pids.add(pid)
        import fcntl, struct, termios
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
        screen = bytearray()

        def pump(limit):
            end = time.monotonic() + limit
            while time.monotonic() < end:
                ready, _, _ = select.select([fd], [], [], 0.1)
                if ready:
                    try:
                        screen.extend(os.read(fd, 65536))
                    except OSError:
                        return

        def type_line(line):
            for char in line:
                os.write(fd, char.encode())
                pump(0.01)
            os.write(fd, b"\r")
        child = None
        for _ in range(6):  # the first keystrokes can land on the splash; retry until the command runs
            pump(3)
            type_line("!sh -c 'echo $$ > c.fifo; exec sleep 300'; echo after")
            child = wait_child(10)
            if child:
                break
        used = []
        for keys, name in ((b"\x04", "ctrl+d"), (b"\x03", "ctrl+c"), (b"\x03", "ctrl+c")):
            os.write(fd, keys)
            used.append(name)
            pump(1)
            if wait_exit([pid], 2)[pid]:
                break
        tui_exited = wait_exit([pid], 5)[pid]
        after = wait_exit([child], SURVIVE_LIMIT) if child else {}
        probe = Client(run.socket, run.client.protocol)
        listed = probe.request({"type": "list"})
        sessions = ((listed or {}).get("data") or {}).get("sessions", [])
        probe.close()
        return {
            "command_started": bool(child), "quit_keys": used, "tui_exited": tui_exited,
            "child_survived_quit": (not after[child]) if child else None,
            "sessions_after_quit": len(sessions),
        }
    finally:
        run.close()



def abort_right_behind_execute(binary):
    """execute_bash and abort_bash in one write, 20 times: how often does the abort miss the run?"""
    run = Fixture(binary)
    try:
        sid = run.session()
        outcomes = {}
        for index in range(20):
            marker = run.root / "work" / f"ran-{index}.marker"
            ids = run.client.send_together([
                {"type": "execute_bash", "activeSessionId": sid, "command": f"touch ran-{index}.marker; sleep 300"},
                {"type": "abort_bash", "activeSessionId": sid}])
            responses = [run.client.response(cid) for cid in ids]
            end = run.client.event("bash_end", 5)
            if end is None:
                outcome = "not aborted (still running 5 s later)"
                run.client.request({"type": "abort_bash", "activeSessionId": sid})
                run.client.event("bash_end", EVENT_LIMIT)
            elif end.get("cancelled"):
                outcome = "cancelled, command ran" if marker.exists() else "cancelled before it ran"
            else:
                outcome = f"ended uncancelled exit {end.get('exitCode')}"
            if not all(r and r.get("success") for r in responses):
                outcome += " (a request failed)"
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        return {"outcomes": outcomes,
                "missed": sum(n for o, n in outcomes.items() if o.startswith("not aborted"))}
    finally:
        run.close()

SCENARIOS = {
    "sighup_supervisor": sighup_supervisor,
    "kill_or_replace_mid_command": kill_or_replace_mid_command,
    "client_disconnect_mid_command": client_disconnect_mid_command,
    "death_by_signal_exit_code": death_by_signal_exit_code,
    "fast_output_slow_reader": fast_output_slow_reader,
    "background_command_slot": background_command_slot,
    "graceful_shutdown_forked": graceful_shutdown_forked,
    "orphaned_worker_mid_command": orphaned_worker_mid_command,
    "overlapping_runs_abort": overlapping_runs_abort,
    "abort_edge_cases": abort_edge_cases,
    "abort_right_behind_execute": abort_right_behind_execute,
    "output_interleaving": output_interleaving,
    "split_utf8_and_ansi": split_utf8_and_ansi,
    "command_reads_stdin": command_reads_stdin,
    "supervisor_sigint_and_double_sigterm": supervisor_sigint_and_double_sigterm,
    "sigkill_worker": sigkill_worker,
    "await_past_client_timeout": await_past_client_timeout,
    "live_stream_memory": live_stream_memory,
    "tui_quit_mid_command": tui_quit_mid_command,
}


CHECKS = {
    "abort_right_behind_execute": [
        ("an abort_bash sent right behind execute_bash cancels the run (20/20)",
         lambda o: o["missed"] == 0),
    ],
    "split_utf8_and_ansi": [
        ("multi-byte characters split across reads are not replaced with U+FFFD",
         lambda o: sum(o["utf8_euro"]["replacement_chars"].values()) == 0),
        ("no ANSI fragment reaches the stored row",
         lambda o: o["ansi_red_x"]["corrupted_lines"]["row"] == 0),
    ],
    "sigkill_worker": [
        ("a SIGKILLed worker's running user command is reaped",
         lambda o: o["running_command"]["old_command_child_survived"] is False),
    ],
    "death_by_signal_exit_code": [
        ("a command killed by a signal reports 128+signal",
         lambda o: [o[k]["exitCode"] for k in ("self_SIGTERM", "self_SIGKILL", "self_SIGINT", "self_SIGSEGV",
                                                "single_command_SIGSEGV")] == [143, 137, 130, 139, 139]),
    ],
    "kill_or_replace_mid_command": [
        ("session kill ends the run and kills the command's child",
         lambda o: o["kill"]["bash_end"] == {"cancelled": True, "exitCode": None} and not o["kill"]["child_survived"]),
    ],
    "sighup_supervisor": [
        ("SIGHUP is handled: the supervisor exits with a status, not by the signal",
         lambda o: o["SIGHUP"]["supervisor_exit"].startswith("exit ")),
    ],
}


def normalized(value):
    """Pids and other run-specific numbers inside text (shell job messages) never count as a difference."""
    if isinstance(value, str):
        return re.sub(r"\b\d{4,}\b", "<n>", value)
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()}
    return value


def diff(reference, other, path=""):
    if isinstance(reference, dict) and isinstance(other, dict):
        out = []
        for key in sorted(set(reference) | set(other)):
            out += diff(reference.get(key), other.get(key), f"{path}.{key}" if path else key)
        return out
    if normalized(reference) == normalized(other):
        return []
    return [{"path": path, "reference": reference, "other": other}]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", action="append",
                        help="label=path, repeatable (first is the reference); default: "
                             "ts=$PA_TS_BINARY rust=$PA_RUST_BINARY")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS))
    parser.add_argument("--receipt")
    parser.add_argument("--repeat", type=int, default=1, help="runs per variant for repeated scenarios")
    parser.add_argument("--check", action="store_true",
                        help="assert the reference behavior on every binary; exit 1 on any failure")
    args = parser.parse_args()
    if not args.binary:
        if not (os.environ.get("PA_TS_BINARY") and os.environ.get("PA_RUST_BINARY")):
            parser.error("pass --binary, or set PA_TS_BINARY and PA_RUST_BINARY")
        args.binary = [f"ts={os.environ['PA_TS_BINARY']}", f"rust={os.environ['PA_RUST_BINARY']}"]
    # Absolute paths: each daemon runs from its own isolated root.
    binaries = [(label, os.path.abspath(path)) for label, path in (item.split("=", 1) for item in args.binary)]
    global REPEAT
    REPEAT = args.repeat
    receipt = {"binaries": {label: path for label, path in binaries}, "scenarios": {}}
    for name in args.scenario or list(SCENARIOS):
        results = {}
        for label, path in binaries:
            try:
                results[label] = SCENARIOS[name](path)
            except Exception as error:  # a failed run is an observation, not a crash of the suite
                results[label] = {"error": f"{type(error).__name__}: {error}"}
        reference = binaries[0][0]
        receipt["scenarios"][name] = {
            "observed": results,
            "differences": {label: diff(results[reference], results[label])
                            for label, _ in binaries[1:]},
        }
        print(f"== {name}")
        for label, _ in binaries:
            print(f"  {label}: {json.dumps(results[label], sort_keys=True)}")
        for label, found in receipt["scenarios"][name]["differences"].items():
            print(f"  {reference} vs {label}: {len(found)} difference(s)")
    failed = 0
    if args.check:
        for name in args.scenario or list(SCENARIOS):
            for description, predicate in CHECKS.get(name, []):
                for label, _ in binaries:
                    observed = receipt["scenarios"][name]["observed"][label]
                    try:
                        ok = "error" not in observed and predicate(observed)
                    except (KeyError, TypeError):
                        ok = False
                    failed += not ok
                    receipt.setdefault("checks", []).append(
                        {"scenario": name, "check": description, "binary": label, "passed": ok})
                    print(f"  CHECK {'PASS' if ok else 'FAIL'} {label}: {name}: {description}")
    if args.receipt:
        Path(args.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
