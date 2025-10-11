#!/usr/bin/env python3
# aggressive low-latency solver for the "sum the list" challenge

from pwn import remote, context
import re
import time

context.log_level = "error"   # quieter, faster

HOST = "software-17.challs.olicyber.it"
PORT = 13000

# require at least one digit inside brackets (non-greedy)
BRACKET_RE = re.compile(rb'\[[^\]]*\d[^\]]*\]', re.DOTALL)
INT_RE = re.compile(rb'[-+]?\d+')

def sum_from_bytes(b):
    nums = INT_RE.findall(b)
    return sum(int(x) for x in nums)

def run_fast():
    r = remote(HOST, PORT, timeout=3)
    buf = bytearray()
    rounds = 0
    tstart = time.time()

    try:
        # read banner quickly (don't wait long)
        try:
            _ = r.recvuntil(b'Invia', timeout=1)
        except Exception:
            _ = r.recv(1024, timeout=0.5) or b''
        # send starter
        r.sendline(b"x")

        # main fast loop: stop after 10 rounds or on EOF/close
        while rounds < 10:
            # tight-read small timeout for low latency
            try:
                chunk = r.recv(timeout=0.05)  # very small timeout
                if chunk:
                    buf.extend(chunk)
            except Exception:
                # no data this tick
                pass

            # look for bracketed array
            m = BRACKET_RE.search(buf)
            if not m:
                # keep the trailing bytes only to prevent buf growth
                if len(buf) > 32768:
                    buf = buf[-8192:]
                continue

            arr = bytes(m.group(0))
            nums = INT_RE.findall(arr)
            if not nums:
                # remove matched slice and continue (shouldn't happen due to regex)
                buf = buf[m.end():]
                continue

            ans = sum(int(x) for x in nums)
            # send answer immediately
            r.sendline(str(ans).encode())
            rounds += 1
            # remove processed slice
            buf = buf[m.end():]

            # minimal status output (won't slow down much)
            print(f"[{rounds}] answered {ans} (elapsed {time.time()-tstart:.3f}s)")

        # attempt to read final output (brief window)
        try:
            tail = r.recvall(timeout=2)
            if tail:
                print("FINAL:\n", tail.decode(errors='ignore'))
        except Exception:
            pass

    finally:
        r.close()
        print("connection closed (total elapsed %.3fs)" % (time.time()-tstart))

if __name__ == "__main__":
    run_fast()
