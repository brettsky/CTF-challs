from pwn import remote
import re

HOST, PORT = "software-17.challs.olicyber.it", 13000
BRACKET_RE = re.compile(rb'\[[^\]]*\d[^\]]*\]')   # match bracketed lists
INT_RE = re.compile(rb'[-+]?\d+')

r = remote(HOST, PORT)
# start the challenge
r.send(b'\n')  # send any char to start

buf = b''
for i in range(10):
    # keep receiving until we find a bracketed array
    while True:
        buf += r.recv(1024)            # read raw bytes
        m = BRACKET_RE.search(buf)
        if m:
            arr_bytes = m.group(0)     # e.g. b'[1, -2, 3]'
            # remove processed part from buffer
            buf = buf[m.end():]
            nums = [int(x) for x in INT_RE.findall(arr_bytes)]
            s = str(sum(nums)).encode() + b'\n'
            r.send(s)
            break

# get final output (flag)
print(r.recvall(timeout=2).decode(errors='ignore'))
r.close()
