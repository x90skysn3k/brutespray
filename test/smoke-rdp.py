#!/usr/bin/env python3
"""Local-only, real-process RDP CLI/TUI regression smoke (Python 3.11+)."""

import argparse
import asyncio
import codecs
from collections import Counter, defaultdict
from dataclasses import dataclass, field
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata


class SmokeFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x80 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + value


def ts_request(token=None, reject=False):
    # [MS-CSSP] TSRequest: version [0], negoTokens [1], errorCode [4].
    body = der(0xa0, der(2, b"\x02"))
    if token is not None:
        body += der(0xa1, der(0x30, der(0x30, der(0xa0, der(4, token)))))
    if reject:
        # Positive ASN.1 INTEGER STATUS_LOGON_FAILURE (0xc000006d).
        body += der(0xa4, der(2, b"\x00\xc0\x00\x00\x6d"))
    return der(0x30, body)


def challenge(kind):
    # [MS-NLMP] CHALLENGE_MESSAGE. Offsets are absolute, not payload-relative.
    versioned = kind != "healthy-unversioned"
    flags = 0xe0888235 | (0x02000000 if versioned else 0)
    header_size = 56 if versioned else 48
    name = "LOCAL".encode("utf-16le")
    info = struct.pack("<HH", 2, len(name)) + name + b"\x00" * 4
    name_len, name_offset = len(name), header_size
    info_len, info_offset = len(info), header_size + len(name)
    payload = name + info
    if kind == "malformed":
        # Reporter: VERSION consumes 56 bytes, but target name points to 48.
        # The old parser computes uint32(48 - 56) == 4294967288.
        name_len, name_offset = 12, 48
        info_len, info_offset = 0, 0
        payload = b"ABCD"
    packet = b"NTLMSSP\x00" + struct.pack("<IHHII", 2, name_len, name_len, name_offset, flags)
    packet += b"12345678" + b"\x00" * 8
    packet += struct.pack("<HHI", info_len, info_len, info_offset)
    if versioned:
        packet += struct.pack("<BBH3sB", 10, 0, 19045, b"\x00" * 3, 15)
    return packet + payload


async def read_der(reader):
    header = await reader.readexactly(2)
    size = header[1]
    if size & 0x80:
        count = size & 0x7f
        if not 1 <= count <= 3:
            raise SmokeFailure("client sent invalid DER length")
        extra = await reader.readexactly(count)
        header += extra
        size = int.from_bytes(extra, "big")
    require(size <= 65536, "client DER frame exceeds 64 KiB")
    return header + await reader.readexactly(size)


@dataclass
class Endpoint:
    kind: str
    port: int = 0
    accepted: int = 0
    negotiated: int = 0
    challenged: int = 0
    authenticated: int = 0
    rejected: int = 0
    errors: list = field(default_factory=list)

    @property
    def key(self):
        return f"127.0.0.1:{self.port}:rdp"


class Fixtures:
    """One asyncio loop serves all loopback targets, including TLS handshakes."""

    def __init__(self, kinds, tls_context):
        self.endpoints = [Endpoint(kind) for kind in kinds]
        self.tls_context = tls_context
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.servers = []
        self.tasks = set()
        self.lock = threading.Lock()

    def bump(self, endpoint, name):
        with self.lock:
            setattr(endpoint, name, getattr(endpoint, name) + 1)

    async def handle(self, endpoint, reader, writer):
        self.tasks.add(asyncio.current_task())
        self.bump(endpoint, "accepted")
        try:
            async with asyncio.timeout(12):
                if endpoint.kind == "silent":
                    # Accept and never reply. Read until the client closes.
                    while await reader.read(4096):
                        pass
                    return
                header = await reader.readexactly(4)
                require(header[:2] == b"\x03\x00", "client did not send TPKT")
                size = int.from_bytes(header[2:4], "big")
                require(7 <= size <= 4096, "invalid client TPKT size")
                await reader.readexactly(size - 4)
                if endpoint.kind == "garbage":
                    writer.write(b"\x00\x01")
                    await writer.drain()
                    return
                # TPKT + X.224 Connection Confirm, selectedProtocol=HYBRID.
                writer.write(bytes.fromhex("030000130ed000000000000200080002000000"))
                await writer.drain()
                await writer.start_tls(self.tls_context, ssl_handshake_timeout=5)
                negotiate = await read_der(reader)
                require(b"NTLMSSP\x00\x01\x00\x00\x00" in negotiate, "missing NTLM NEGOTIATE")
                self.bump(endpoint, "negotiated")
                writer.write(ts_request(challenge(endpoint.kind)))
                await writer.drain()
                self.bump(endpoint, "challenged")
                if endpoint.kind == "malformed":
                    # A fixed client must reject this challenge, not authenticate.
                    await reader.read(4096)
                    return
                authenticate = await read_der(reader)
                require(b"NTLMSSP\x00\x03\x00\x00\x00" in authenticate, "missing NTLM AUTHENTICATE")
                self.bump(endpoint, "authenticated")
                writer.write(ts_request(reject=True))
                await writer.drain()
                self.bump(endpoint, "rejected")
                # Wait for the peer to consume the explicit error; EOF is not
                # being used as a substitute for an authentication rejection.
                await reader.read(4096)
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError, ssl.SSLError):
            pass  # A client timeout/close is expected for hostile fixtures.
        except Exception as error:
            with self.lock:
                endpoint.errors.append(f"{type(error).__name__}: {error}")
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), .5)
            except (ConnectionError, TimeoutError, ssl.SSLError):
                pass
            self.tasks.discard(asyncio.current_task())

    async def start(self):
        for endpoint in self.endpoints:
            server = await asyncio.start_server(
                lambda r, w, e=endpoint: self.handle(e, r, w), "127.0.0.1", 0,
                family=socket.AF_INET, backlog=4096)
            endpoint.port = server.sockets[0].getsockname()[1]
            self.servers.append(server)

    def __enter__(self):
        self.thread.start()
        asyncio.run_coroutine_threadsafe(self.start(), self.loop).result(10)
        return self

    async def stop(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)

    def __exit__(self, *_):
        try:
            asyncio.run_coroutine_threadsafe(self.stop(), self.loop).result(10)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(5)
            self.loop.close()

    def counts(self):
        with self.lock:
            return {e.key: e.accepted for e in self.endpoints}


class Terminal:
    """Small VT screen for Bubble Tea's cursor/erase operations, not a renderer."""

    def __init__(self, rows=42, cols=160):
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.pending = ""
        self.row = self.col = 0
        self.saved = (0, 0)
        self.resize(rows, cols)

    def resize(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.row = min(self.row, rows - 1)
        self.col = min(self.col, cols - 1)

    def text(self):
        return "\n".join("".join(row).rstrip() for row in self.grid)

    def csi(self, arguments, command):
        values = arguments.lstrip("?>").split(";")
        numbers = [int(v) if v.isdigit() else 0 for v in values]
        n = numbers[0] or 1
        if command in "Hf":
            self.row = (numbers[0] or 1) - 1
            self.col = ((numbers[1] if len(numbers) > 1 else 1) or 1) - 1
        elif command == "A":
            self.row -= n
        elif command in "Be":
            self.row += n
        elif command in "Ca":
            self.col += n
        elif command == "D":
            self.col -= n
        elif command == "E":
            self.row += n
            self.col = 0
        elif command == "F":
            self.row -= n
            self.col = 0
        elif command in "G`":
            self.col = n - 1
        elif command == "d":
            self.row = n - 1
        elif command == "J":
            mode = numbers[0]
            if mode in (2, 3):
                self.grid = [[" "] * self.cols for _ in range(self.rows)]
            elif mode == 0:
                self.grid[self.row][self.col:] = [" "] * (self.cols - self.col)
                for row in range(self.row + 1, self.rows):
                    self.grid[row] = [" "] * self.cols
        elif command == "K":
            mode = numbers[0]
            start, end = (0, self.cols) if mode == 2 else ((0, self.col + 1) if mode == 1 else (self.col, self.cols))
            self.grid[self.row][start:end] = [" "] * (end - start)
        elif command == "s":
            self.saved = (self.row, self.col)
        elif command == "u":
            self.row, self.col = self.saved
        self.row = max(0, min(self.row, self.rows - 1))
        self.col = max(0, min(self.col, self.cols - 1))

    def feed(self, data):
        self.pending += self.decoder.decode(data)
        text, index = self.pending, 0
        replies = []
        while index < len(text):
            char = text[index]
            if char == "\x1b":
                if index + 1 >= len(text):
                    break
                following = text[index + 1]
                if following == "[":
                    end = index + 2
                    while end < len(text) and not "@" <= text[end] <= "~":
                        end += 1
                    if end == len(text):
                        break
                    arguments, command = text[index + 2:end], text[end]
                    if command == "n" and arguments == "6":
                        replies.append(b"\x1b[1;1R")
                    elif command == "c":
                        replies.append(b"\x1b[?1;2c")
                    else:
                        self.csi(arguments, command)
                    index = end + 1
                    continue
                if following == "]":
                    end = index + 2
                    while end < len(text) and text[end] != "\x07" and text[end:end + 2] != "\x1b\\":
                        end += 1
                    if end == len(text) or (text[end] == "\x1b" and end + 1 == len(text)):
                        break
                    query = text[index + 2:end]
                    if query in ("10;?", "11;?"):
                        color = b"ffff/ffff/ffff" if query.startswith("10") else b"0000/0000/0000"
                        replies.append(b"\x1b]" + query[:2].encode() + b";rgb:" + color + b"\x1b\\")
                    index = end + (1 if text[end] == "\x07" else 2)
                    continue
                if following == "7":
                    self.saved = (self.row, self.col)
                elif following == "8":
                    self.row, self.col = self.saved
                index += 2
                continue
            if char == "\r":
                self.col = 0
            elif char == "\n":
                self.row += 1
                if self.row >= self.rows:
                    self.grid.pop(0)
                    self.grid.append([" "] * self.cols)
                    self.row = self.rows - 1
            elif char == "\b":
                self.col = max(0, self.col - 1)
            elif char == "\t":
                self.col = min(self.cols - 1, (self.col // 8 + 1) * 8)
            elif char >= " " and char != "\x7f":
                width = 0 if unicodedata.combining(char) else (2 if unicodedata.east_asian_width(char) in "WF" else 1)
                if width:
                    self.grid[self.row][self.col] = char
                    if width == 2 and self.col + 1 < self.cols:
                        self.grid[self.row][self.col + 1] = ""
                    self.col = min(self.cols - 1, self.col + width)
            index += 1
        self.pending = text[index:]
        return replies


class Process:
    def __init__(self, command, directory, tui):
        self.tui = tui
        self.lock = threading.Lock()
        self.terminal = Terminal()
        self.suffix = bytearray()
        self.total_output = 0
        self.saved_output = 0
        self.reader_error = None
        self.command = command
        self.directory = directory
        self.log = (directory / "transcript.raw").open("wb")
        environment = dict(os.environ, TERM="xterm-256color", COLORTERM="truecolor", LANG="C.UTF-8", GOTRACEBACK="all")
        if tui:
            self.fd, slave = pty.openpty()
            fcntl.ioctl(slave, __import__("termios").TIOCSWINSZ, struct.pack("HHHH", 42, 160, 0, 0))
            self.process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, cwd=directory, env=environment, start_new_session=True)
            os.close(slave)
        else:
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=directory, env=environment, start_new_session=True)
            self.fd = self.process.stdout.fileno()
        self.thread = threading.Thread(target=self.drain, daemon=True)
        self.thread.start()

    def drain(self):
        try:
            while True:
                ready, _, _ = select.select([self.fd], [], [], .1)
                if not ready:
                    if self.process.poll() is not None:
                        break
                    continue
                try:
                    data = os.read(self.fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO and self.tui:
                        break
                    raise
                if not data:
                    break
                with self.lock:
                    self.total_output += len(data)
                    # Bound both memory and diagnostic disk output even for a
                    # regression that keeps attempting millions of credentials.
                    remaining = 64 * 1024 * 1024 - self.saved_output
                    if remaining > 0:
                        self.log.write(data[:remaining])
                        self.saved_output += min(remaining, len(data))
                    self.suffix.extend(data)
                    if len(self.suffix) > 2 * 1024 * 1024:
                        del self.suffix[:-2 * 1024 * 1024]
                    replies = self.terminal.feed(data) if self.tui else []
                for reply in replies:
                    os.write(self.fd, reply)
        except Exception as error:
            self.reader_error = str(error)
        finally:
            self.log.close()

    def text(self):
        with self.lock:
            return self.terminal.text() if self.tui else self.suffix.decode("utf-8", "replace")

    def send(self, data):
        os.write(self.fd, data)

    def resize(self, rows, cols):
        with self.lock:
            self.terminal.resize(rows, cols)
        fcntl.ioctl(self.fd, __import__("termios").TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.process.send_signal(signal.SIGWINCH)

    def wait_for(self, predicate, description, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            require(not self.reader_error, f"output reader failed: {self.reader_error}")
            if predicate():
                return
            require(self.process.poll() is None, f"process exited {self.process.returncode} before {description}")
            time.sleep(.025)
        raise SmokeFailure(f"timed out waiting for {description}")

    def visible(self, text, timeout=10):
        self.wait_for(lambda: text in self.text(), repr(text), timeout)

    def terminate(self, stack=False):
        if getattr(self, "closed", False):
            return
        self.closed = True
        if self.process.poll() is None:
            if stack:
                self.process.send_signal(signal.SIGQUIT)
                try:
                    self.process.wait(3)
                except subprocess.TimeoutExpired:
                    pass
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(5)
        self.thread.join(3)
        if self.tui:
            os.close(self.fd)
        elif self.process.stdout:
            self.process.stdout.close()


def entries(path):
    if not path.exists():
        return []
    with path.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def exercise_tui(process, fixtures, host_parallelism):
    process.wait_for(lambda: any(fixtures.counts().values()), "first real socket acceptance")
    process.visible("BRUTESPRAY")
    process.send(b"\x1b")
    process.visible("All hosts paused")
    process.send(b"\r")
    process.visible("Resumed all hosts")
    # All -> By Host -> By Service -> Completed -> ... -> Settings.
    process.send(b"l")
    process.visible("127.0.0.1:")
    process.send(b"llllll")
    process.visible("Settings & Stats")
    process.send(b"jj")  # focus content, then Parallel Hosts
    require("All hosts completed." not in process.text(), "scan finished before live parallelism adjustment")
    process.send(b"h")
    process.wait_for(lambda: re.search(r"Parallel Hosts\s+◀\s*" + str(host_parallelism - 1) + r"\s*▶", process.text()), "live parallelism decrement")
    process.send(b"l")
    process.wait_for(lambda: re.search(r"Parallel Hosts\s+◀\s*" + str(host_parallelism) + r"\s*▶", process.text()), "live parallelism restore")
    process.resize(32, 120)
    process.visible("Settings & Stats")
    process.resize(48, 180)
    process.visible("Settings & Stats")
    # Return from selected field 1 to the tab bar, then Completed (index 3).
    process.send(b"kkhhhh")
    process.visible("Completed")
    require(process.process.poll() is None, "TUI exited during interaction")


RETRY_TOLERANCE = 4


def validate(directory, fixtures, expected, json_output, tui):
    records = entries(directory / "checkpoint.jsonl")
    checkpoint = json.loads((directory / "checkpoint.json").read_text())
    attempts = defaultdict(list)
    started, completed = Counter(), Counter()
    completed_totals = {}
    completed_seen = False
    admitted_after_completion = False
    for record in records:
        key = f"{record['host']}:{record['port']}:{record['service']}"
        if record["type"] == "attempt":
            attempts[key].append(record)
        elif record["type"] == "host_started":
            started[key] += 1
            admitted_after_completion |= completed_seen
        elif record["type"] == "host_completed":
            completed[key] += 1
            completed_seen = True
            completed_totals[key] = record.get("total_attempts", 0)
    expected_keys = set(expected)
    require(set(started) == expected_keys and all(n == 1 for n in started.values()), "session host_started does not cover every target exactly once")
    require(set(completed) == expected_keys and all(n == 1 for n in completed.values()), "session host_completed does not cover every target exactly once")
    require({key for key, done in checkpoint["completed_hosts"].items() if done} == expected_keys, "checkpoint did not mark every target complete")
    require(not checkpoint.get("successful_creds"), "fixture unexpectedly recorded successful credentials")
    counts = fixtures.counts()
    retried_total = 0
    for endpoint in fixtures.endpoints:
        key = endpoint.key
        count = expected[key]
        require(not endpoint.errors, f"{key}: fixture errors: {endpoint.errors}")
        first_pass = [r for r in attempts[key] if not r.get("retrying")]
        retries = [r for r in attempts[key] if r.get("retrying")]
        # Every credential must be attempted exactly once by the first
        # pass. The recovery pass may legitimately re-dial a credential
        # whose first dial hit a connection blip under co-running load,
        # so total sockets/rows may exceed the first-pass budget — but
        # only via retrying=true rows for already-covered credentials,
        # and never beyond the tolerance. Dead hosts are still exact:
        # the tripped breaker suppresses the recovery pass.
        creds = [(r.get("user"), r.get("password")) for r in first_pass]
        require(len(creds) == len(set(creds)) and len(creds) == count,
                f"{key}: first pass covered {len(set(creds))}/{len(creds)} credentials, want exactly {count} unique")
        require(all((r.get("user"), r.get("password")) in set(creds) for r in retries),
                f"{key}: recovery pass attempted a credential the first pass never reached")
        require(len(retries) <= RETRY_TOLERANCE, f"{key}: {len(retries)} recovery retries exceed tolerance {RETRY_TOLERANCE}")
        if not endpoint.kind.startswith("healthy"):
            require(not retries, f"{key}: dead host retried credentials despite tripped breaker")
            require(counts[key] == count, f"{key} ({endpoint.kind}): real TCP attempts {counts[key]}, expected exactly {count}")
        counts_ok = counts[key] == len(attempts[key])
        if not counts_ok:
            # A dial whose accept lands after the client deadline (or is
            # retransmitted) shifts fixture accepts vs. client-visible
            # dials by at most a few under saturation load.
            require(abs(counts[key] - len(attempts[key])) <= RETRY_TOLERANCE,
                    f"{key}: real TCP attempts {counts[key}] differ from session rows {len(attempts[key])}")
        completed_total = completed_totals.get(key, 0)
        require(completed_total == len(attempts[key]), f"{key}: host_completed total_attempts {completed_total} differ from session rows {len(attempts[key])}")
        require(checkpoint["attempted_creds"].get(key) == len(first_pass), f"{key}: checkpoint attempt count differs from first-pass coverage")
        auth_rows = [r for r in attempts[key] if r.get("status") == "auth_failure"]
        for record in attempts[key]:
            require(not record.get("success"), f"{key}: unexpected success: {record}")
            require(record.get("status") != "module_panic_recovered", f"{key}: recovered module panic is not an acceptable result")
            if endpoint.kind.startswith("healthy"):
                # Each credential's final recorded outcome must be the
                # explicit CredSSP rejection; a connection blip on the
                # first pass is acceptable only when a paired retry row
                # ends in auth_failure for the same credential.
                if record.get("retrying"):
                    require(record.get("connected") and record.get("status") == "auth_failure", f"{key}: retry row was not an auth_failure: {record}")
            else:
                require(not record.get("connected"), f"{key}: hostile fixture counted as a successful connection: {record}")
                require(record.get("status") in ("connection_failure", "module_timeout"), f"{key}: unexpected hostile-fixture status: {record}")
        if endpoint.kind.startswith("healthy"):
            final = {}
            for record in attempts[key]:
                final[(record.get("user"), record.get("password"))] = record
            require(all(r.get("connected") and r.get("status") == "auth_failure" for r in final.values()),
                    f"{key}: a credential ended on a non-auth_failure outcome")
            require(len(auth_rows) >= count, f"{key}: {len(auth_rows)} auth_failure rows, want at least {count}")
            progressed = endpoint.negotiated
            require(endpoint.negotiated == endpoint.challenged == endpoint.authenticated == endpoint.rejected, f"{key}: NTLM stage counters disagree: {endpoint}")
            require(progressed >= count - RETRY_TOLERANCE and progressed <= len(auth_rows) + RETRY_TOLERANCE,
                    f"{key}: NTLM challenge coverage {progressed} inconsistent with {len(auth_rows)} auth failures")
        elif endpoint.kind not in ("garbage", "silent"):
            require(endpoint.negotiated == endpoint.challenged, f"{key}: NTLM negotiate/challenge counters disagree")
            require(endpoint.negotiated >= count - RETRY_TOLERANCE, f"{key}: only {endpoint.negotiated} NTLM challenges exercised, want >= {count - RETRY_TOLERANCE}")
            require(endpoint.authenticated == 0, f"{key}: malformed challenge client must never send AUTHENTICATE, got {endpoint.authenticated}")
        retried_total += len(retries)
    if json_output and not tui:
        output_records = []
        with (directory / "transcript.raw").open(errors="replace") as stream:
            for line in stream:
                if line.startswith("{"):
                    record = json.loads(line)
                    if record.get("service") == "rdp" and "connected" in record:
                        output_records.append(record)
        require(len(output_records) == sum(counts.values()), "JSON stdout attempt count differs from real sockets")
        require(all(not record.get("success") for record in output_records), "JSON stdout reports false authentication success")
        for record in output_records:
            key = f"{record['host']}:{record['port']}:rdp"
            healthy = next(e.kind.startswith("healthy") for e in fixtures.endpoints if e.key == key)
            require(bool(record["connected"]) == healthy, f"{key}: JSON connection classification differs from fixture")
            if healthy:
                require(record.get("status_code") == "auth_failure", f"{key}: JSON auth status code differs")
    return {"hosts_completed": len(completed), "real_tcp_attempts": sum(counts.values()),
            "recovery_retries": retried_total,
            "session_attempts": sum(map(len, attempts.values())), "checkpoint_attempts": sum(checkpoint["attempted_creds"].values()),
            "dead_host_attempts_max": max((counts[e.key] for e in fixtures.endpoints if not e.kind.startswith("healthy")), default=0),
            "healthy_auth_failures": sum(len(attempts[e.key]) for e in fixtures.endpoints if e.kind.startswith("healthy")),
            "queued_host_admitted_after_completion": admitted_after_completion}


CASES = {
    "garbage-legacy-t5": ("garbage", 5, False, False, True),
    "garbage-json-t50": ("garbage", 50, True, False, True),
    "silent-json-t50": ("silent", 50, True, False, True),
    "malformed-json": ("malformed", 50, True, False, False),
    "healthy-json": ("healthy", 50, True, False, False),
    "silent-tui-t50": ("silent", 50, False, True, True),
}


def run_case(args, name, root, context):
    kind, parallelism, json_output, tui, large = CASES[name]
    directory = root / name
    directory.mkdir()
    users = directory / "users.txt"
    passwords = directory / "passwords.txt"
    users.write_text("".join(f"user{i:04d}\n" for i in range(1000 if large else 1)))
    passwords.write_text("".join(f"pass{i:04d}\n" for i in range(1000 if large else 16)))
    kinds = [("healthy-versioned" if i % 2 == 0 else "healthy-unversioned") if kind == "healthy" else kind for i in range(64)]
    with Fixtures(kinds, context) as fixtures:
        expected = {e.key: 16 if e.kind.startswith("healthy") else 10 for e in fixtures.endpoints}
        command = [str(args.binary), "-u", str(users), "-p", str(passwords), "-t", "30", "-T", str(parallelism),
                   "-w", "3s" if tui else ("10s" if kind in ("malformed", "healthy") else "500ms"),
                   "-r", "0", "-skip-policy", "aggressive", "-max-conn-fails", "10", "-no-rdp-scan",
                   "-checkpoint", str(directory / "checkpoint.json"), "-o", str(directory / "output"), "-q"]
        if not tui:
            command += ["-no-tui", "-nc"]
        if json_output:
            command += ["--output-format", "json"]
        for endpoint in fixtures.endpoints:
            command += ["-H", f"rdp://127.0.0.1:{endpoint.port}"]
        (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        process = Process(command, directory, tui)
        started = time.monotonic()
        try:
            if tui:
                exercise_tui(process, fixtures, parallelism)
            def finished():
                counts = fixtures.counts()
                excess = [(key, count, expected[key]) for key, count in counts.items()
                          if count > expected[key] + (RETRY_TOLERANCE if any(e.key == key and e.kind.startswith("healthy") for e in fixtures.endpoints) else 0)]
                require(not excess, f"real socket attempt cap exceeded: {excess[:8]}")
                if tui:
                    return "All hosts completed. Press Ctrl+C to exit." in process.text()
                return process.process.poll() is not None
            if tui:
                process.wait_for(finished, "rendered all-hosts completion", args.timeout)
                process.visible("Avg Response")
                screen = process.text()
                require("All hosts completed. Press Ctrl+C to exit." in screen, "final rendered screen lacks completion status")
                (directory / "completed-screen.txt").write_text(screen + "\n")
                process.send(b"\x03")
                process.visible("Press Ctrl+C again to quit")
                process.send(b"\x03")
                process.process.wait(10)
            else:
                deadline = time.monotonic() + args.timeout
                while not finished():
                    require(time.monotonic() < deadline, f"case exceeded {args.timeout}s")
                    require(not process.reader_error, f"output reader failed: {process.reader_error}")
                    time.sleep(.025)
            process.thread.join(3)
            require(process.process.returncode == 0, f"binary exit status {process.process.returncode}")
            require(not process.reader_error, f"output reader failed: {process.reader_error}")
            transcript = bytes(process.suffix).decode("utf-8", "replace")
            require(not re.search(r"panic:|fatal error:|module_panic_recovered|runtime error:", transcript), "panic/fatal error in binary output")
            summary = validate(directory, fixtures, expected, json_output, tui)
            (directory / "fixtures.json").write_text(json.dumps([vars(e) for e in fixtures.endpoints], indent=2) + "\n")
            if parallelism == 5:
                require(summary["queued_host_admitted_after_completion"], "no queued host was admitted after an earlier host completed")
            summary.update(case=name, mode="tui" if tui else ("json" if json_output else "legacy"),
                           threads_per_host=30, concurrent_hosts=parallelism,
                           combinations_per_host=1_000_000 if large else 16,
                           healthy_versioned_hosts=sum(e.kind == "healthy-versioned" for e in fixtures.endpoints),
                           healthy_unversioned_hosts=sum(e.kind == "healthy-unversioned" for e in fixtures.endpoints),
                           tui_interactions_completed=tui,
                           elapsed_seconds=round(time.monotonic() - started, 3), assertions="passed")
            (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            return summary
        except Exception as error:
            process.terminate(stack=True)
            counts = fixtures.counts()
            (directory / "failure.json").write_text(json.dumps({"error": str(error), "real_tcp_attempts": counts}, indent=2) + "\n")
            with process.lock:
                tail = bytes(process.suffix[-24000:]).decode("utf-8", "replace")
            raise SmokeFailure(f"{name}: {error}\nArtifacts: {directory}\nOutput suffix (SIGQUIT stack on timeout/failure):\n{tail}") from error
        finally:
            process.terminate()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  go build -o /tmp/brutespray-smoke .
  python3 test/smoke-rdp.py --binary /tmp/brutespray-smoke
  python3 test/smoke-rdp.py --binary /tmp/brutespray-smoke --case healthy-json --artifacts /tmp/rdp-proof

Requires Python 3.11+, openssl, and a prebuilt binary. No Docker, external
network, terminal emulator, or Python packages. All sockets bind 127.0.0.1
on ephemeral ports. Temporary credentials/checkpoints are always deleted;
--artifacts copies diagnostic evidence out before cleanup (including failures).
A failed/hung binary receives SIGQUIT for a Go stack, then is killed if needed.
Each case has 64 targets; large cases use 1000 users x 1000 passwords per host.
""")
    parser.add_argument("--binary", required=True, type=Path, help="path to the already-built brutespray binary")
    parser.add_argument("--case", choices=list(CASES), action="append", help="run only this case (repeatable; default all six)")
    parser.add_argument("--timeout", type=float, default=90, help="scan-completion deadline per case in seconds (default 90)")
    parser.add_argument("--artifacts", type=Path, help="copy transcripts, commands, session/checkpoint and summaries here")
    args = parser.parse_args()
    args.binary = args.binary.expanduser().resolve()
    require(sys.version_info >= (3, 11), "Python 3.11+ is required")
    require(args.binary.is_file() and os.access(args.binary, os.X_OK), f"not an executable binary: {args.binary}")
    require(args.timeout > 0, "--timeout must be positive")
    require(shutil.which("openssl"), "openssl is required to generate a temporary loopback TLS certificate")
    results = []
    with tempfile.TemporaryDirectory(prefix="brutespray-rdp-smoke-") as temporary:
        root = Path(temporary)
        certificate, key = root / "fixture-cert.pem", root / "fixture-key.pem"
        cert_result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                                      "-out", str(certificate), "-days", "1", "-subj", "/CN=localhost"],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        require(cert_result.returncode == 0, f"openssl certificate generation failed: {cert_result.stderr.decode(errors='replace')}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        try:
            for name in args.case or CASES:
                summary = run_case(args, name, root, context)
                results.append(summary)
                print(json.dumps(summary, sort_keys=True), flush=True)
            print(json.dumps({"result": "PASS", "cases": len(results), "hosts_completed": sum(r["hosts_completed"] for r in results),
                              "real_tcp_attempts": sum(r["real_tcp_attempts"] for r in results)}, sort_keys=True), flush=True)
        finally:
            if args.artifacts:
                destination = args.artifacts.expanduser().resolve()
                destination.mkdir(parents=True, exist_ok=True)
                for child in root.iterdir():
                    if child.is_dir():
                        shutil.copytree(child, destination / child.name, dirs_exist_ok=True)
                (destination / "summary.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (SmokeFailure, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
