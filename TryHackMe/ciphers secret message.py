cipher = "a_up4qr_kaiaf0_bujktaz_qm_su4ux_cpbq_ETZ_rhrudm"

def dec(s: str) -> str:
    out = []
    for i, c in enumerate(s):
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - base - i) % 26 + base))
        else:
            out.append(c)
    return "".join(out)

print(dec(cipher))