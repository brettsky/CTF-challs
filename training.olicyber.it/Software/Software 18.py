'''
In this challenge you will see how to use the packing and unpacking functions that pwntools offers.

These are useful when developing exploits as they allow you to convert, for example, memory addresses in numeric form into their representation in little or big endian bytes.

Pwntools offers wrappers for the structpython library (which offers struct.pack).

p64(num, endianness="little", ...)Packs a 64-bit integer
p32(num, endianness="little", ...)Packs a 32-bit integer
u64(data, endianness="little", ...)Unpacks 64-bit integers
u32(data, endianness="little", ...)Unpacks 32-bit integers
For example:

p64(0x401020) -> b"\x20\x10\x40\x00\x00\x00\x00\x00"
u32(b"\x00\x50\x40\x00") -> 0x405000
You can find more information in the relevant documentation

This challenge's binary will ask you to perform some conversion operations using pwntools' packing functions.

You can connect to the remote service with the command:

nc software-18.challs.olicyber.it 13001


1 . Connect to the remote service and see the challenge (nc software-18.challs.olicyber.it 13001)

    We see the challenge is 

    *****************************************************************
* Welcome to the second Pwntools challenge                        *
* You will receive a list of numbers and you will have to return them to me          *
* packed at 64 or 32 bits                                          *
* If you are fast enough, you will get the flag                      *
* You will have to complete 100 steps in 10 seconds                     *
************************* ****************************************...
 Send any character to start ...


 *****************************************************************

 To send any character to start we use the following code:

'''
from pwn import *
import ast
import re

HOST = "software-18.challs.olicyber.it"
PORT = 13001

# quiet logs for speed
context.log_level = "warning"

# Connect to the server
r = remote(HOST, PORT)

# Send any character (newline is safest) to start the challenge
r.sendline(b"")

# Regex helpers
BRACKET_RE = re.compile(rb"\[[^\]]*\]")
INT_RE = re.compile(rb"[-+]?\d+")
BITS_RE = re.compile(rb"(32|64)\s*bit", re.IGNORECASE)
ENDIAN_RE = re.compile(rb"\b(little|big)\b", re.IGNORECASE)

def parse_round_prompt(prompt_bytes):
    """Extract (bits, endian, numbers) from the current round prompt bytes."""
    # default assumptions
    bits = 64
    endian = "little"

    m_bits = BITS_RE.search(prompt_bytes)
    if m_bits:
        bits = int(m_bits.group(1))

    m_endian = ENDIAN_RE.search(prompt_bytes)
    if m_endian:
        endian = m_endian.group(1).decode().lower()

    m_arr = BRACKET_RE.search(prompt_bytes)
    if not m_arr:
        # fallback: accumulate more after caller
        return None

    try:
        nums = [int(x) for x in INT_RE.findall(m_arr.group(0))]
    except Exception:
        # last resort using ast if text is clean
        try:
            nums = ast.literal_eval(m_arr.group(0).decode())
        except Exception:
            return None

    return bits, endian, nums

# Run challenge loop
rounds = 100
buf = b""
round_logs = []
for _ in range(rounds):
    # accumulate until we can parse a full prompt with a bracketed list
    parsed = parse_round_prompt(buf)
    while parsed is None:
        try:
            chunk = r.recv(1024)
        except EOFError:
            # connection closed unexpectedly
            buf = b""
            break
        if not chunk:
            continue
        buf += chunk
        parsed = parse_round_prompt(buf)

    if not parsed:
        break

    bits, endian, nums = parsed

    # consume up to and including the parsed list to keep buffer small
    m = BRACKET_RE.search(buf)
    if m:
        buf = buf[m.end():]
    else:
        buf = b""

    # pack numbers
    out = bytearray()
    if bits == 64:
        for n in nums:
            out += p64(n, endianness=endian, signed=(n < 0))
    else:
        for n in nums:
            out += p32(n, endianness=endian, signed=(n < 0))

    # send raw bytes (no newline)
    r.send(bytes(out))

    # store log for this round (print later to avoid timing issues)
    try:
        arr_match = BRACKET_RE.search(buf)
        arr_text = arr_match.group(0).decode(errors='ignore') if arr_match else str(nums)
    except Exception:
        arr_text = str(nums)
    round_logs.append({
        "bits": bits,
        "endian": endian,
        "numbers": nums,
        "array_text": arr_text,
        "packed_hex": bytes(out).hex()
    })

# print final output (likely contains the flag)
try:
    final = r.recvall(timeout=2)
except EOFError:
    final = b""

# print round logs
for i, log in enumerate(round_logs, 1):
    print(f"=== ROUND {i} ===")
    print(f"bits: {log['bits']}  endian: {log['endian']}")
    print(f"numbers: {log['numbers']}")
    print(f"packed_hex: {log['packed_hex']}")

# print final output (likely contains the flag)
if final:
    try:
        print(final.decode(errors='ignore'))
    except Exception:
        print(final)

r.close()