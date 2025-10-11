#!/usr/bin/env python3
# aggressive, configurable low-latency solver for the "sum the list" challenge
# Usage: python3 solver.py --latency-cpu-tradeoff 0.002 --recv-timeout 0.05 --rounds 10

from pwn import remote, context
import re
import time
import argparse
import sys
import traceback

context.log_level = "error"  # quieter, faster

DEFAULT_HOST = "software-17.challs.olicyber.it"
DEFAULT_PORT = 13000

# Strict regex: match arrays of integers separated by commas, e.g. [1, -2, 3]
BRACKET_STRICT_RE = re.compile(rb'\[\s*[-+]?\d+(?:\s*,\s*[-+]?\d+)*\s*\]', re.DOTALL)

# Fallback looser regex that requires at least one digit inside brackets
BRACKET_LOOSE_RE = re.compile(rb'\[[^\]]*\d[^\]]*\]', re.DOTALL)

# Integer regex
INT_RE = re.compile(rb'[-+]?\d+')

def sum_from_bytes(b: bytes) -> int:
    nums = INT_RE.findall(b)
    return sum(int(x) for x in nums)

def is_timeout_exc(e: Exception) -> bool:
    """Best-effort detection if an exception appears to be a recv timeout."""
    if isinstance(e, TimeoutError):
        return True
    s = str(e).lower()
    return ("timed out" in s) or ("timeout" in s) or ("time out" in s)

def run_fast(host: str, port: int, rounds_target: int, recv_timeout: float, latency_sleep: float):
    r = remote(host, port, timeout=3)
    buf = bytearray()
    rounds = 0
    tstart = time.time()

    try:
        # quick banner read (don't block long)
        try:
            _ = r.recvuntil(b'Invia', timeout=1)
        except Exception:
            # fallback quick read
            try:
                _ = r.recv(1024, timeout=0.5) or b''
            except Exception:
                # ignore banner read failures, continue
                pass

        # start the challenge
        try:
            r.sendline(b"x")
        except Exception as e:
            print("Failed to send start byte:", e, file=sys.stderr)
            # still try to continue; maybe server accepts without explicit start

        while rounds < rounds_target:
            # tight poll for incoming data
            try:
                chunk = r.recv(timeout=recv_timeout)
                if chunk:
                    buf.extend(chunk)
            except EOFError:
                # Remote closed the connection — treat as graceful end.
                try:
                    tail = r.recvall(timeout=1)
                    if tail:
                        buf.extend(tail)
                except Exception:
                    # ignore further read problems
                    pass
                print("Remote closed connection (EOF). Breaking receive loop.")
                break
            except Exception as e:
                if is_timeout_exc(e):
                    # No data this tick — sleep a configurable tiny amount to reduce CPU spin
                    if latency_sleep > 0:
                        time.sleep(latency_sleep)
                    # continue main loop
                    pass
                else:
                    # non-timeout, non-EOF error — print a helpful trace and re-raise
                    print("Non-timeout recv error:", file=sys.stderr)
                    traceback.print_exc()
                    raise

            # Prefer strict regex first for reliability; fallback to loose only if strict doesn't match
            m = BRACKET_STRICT_RE.search(buf)
            if not m:
                m = BRACKET_LOOSE_RE.search(buf)

            if not m:
                # trim buffer in-place to avoid unbounded growth
                if len(buf) > 32768:
                    # keep last 8192 bytes
                    del buf[:-8192]
                continue

            arr = bytes(m.group(0))
            nums = INT_RE.findall(arr)
            if not nums:
                # remove matched slice and continue (defensive)
                del buf[:m.end()]
                continue

            ans = sum(int(x) for x in nums)
            try:
                r.sendline(str(ans).encode())
            except Exception as e:
                print("Error sending answer:", e, file=sys.stderr)
                raise

            rounds += 1
            # remove processed slice in-place (faster than creating a new bytearray)
            del buf[:m.end()]

            # minimal status output — kept small to avoid large I/O overhead
            print(f"[{rounds}] answered {ans} (elapsed {time.time()-tstart:.3f}s)")

        # Try to read any final output (be tolerant of EOF/other exceptions)
        try:
            tail = r.recvall(timeout=2)
            if tail:
                print("FINAL:\n", tail.decode(errors='ignore'))
        except EOFError:
            # EOF already reached; nothing more to read
            pass
        except Exception:
            # ignore other read issues here
            pass

    finally:
        try:
            r.close()
        except Exception:
            pass
        print("connection closed (total elapsed %.3fs)" % (time.time() - tstart))

def parse_args():
    p = argparse.ArgumentParser(description="Low-latency solver for 'sum the list' challenge")
    p.add_argument("--host", default=DEFAULT_HOST, help="challenge host")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="challenge port")
    p.add_argument("--rounds", type=int, default=10, help="number of rounds to solve (default 10 for typical CTF challenge)")
    p.add_argument(
        "--recv-timeout",
        type=float,
        default=0.05,
        help="timeout (seconds) passed to recv() on each poll — smaller => lower latency, less reliable on slow networks",
    )
    p.add_argument(
        "--latency-cpu-tradeoff",
        type=float,
        default=0.002,
        help="sleep (seconds) when no data received this tick to reduce CPU spin; set to 0 for pure busy-wait",
    )
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    try:
        run_fast(
            host=args.host,
            port=args.port,
            rounds_target=args.rounds,
            recv_timeout=args.recv_timeout,
            latency_sleep=args.latency_cpu_tradeoff,
        )
    except KeyboardInterrupt:
        print("Interrupted by user.")
    except Exception as e:
        print("Fatal error:", e, file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
