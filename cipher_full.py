#!/usr/bin/env python3
# cipher_full.py
# Enhanced: Hill -> Vigenere -> Playfair
# Includes banners for every stage (encryption, decryption, analysis, attack)

import itertools
import math
import time
from collections import Counter

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPH)}
I2A = {i: c for i, c in enumerate(ALPH)}

# ---------------------------
# Utility + formatting
# ---------------------------
def banner(title: str):
    print("\n" + "=" * 80)
    print(f"====================   {title.upper()}   ====================")
    print("=" * 80 + "\n")

def sanitize(s: str) -> str:
    return "".join(c for c in s.upper() if c.isalpha())

# ---------------------------
# Hill 2×2 cipher
# ---------------------------
def modinv(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def det2(M): 
    a, b, c, d = M
    return (a * d - b * c) % 26

def invM2(M):
    a, b, c, d = M
    det = det2(M)
    inv = modinv(det, 26)
    if inv is None:
        return None
    return [
        (d * inv) % 26,
        (-b * inv) % 26,
        (-c * inv) % 26,
        (a * inv) % 26,
    ]

def pairs(s):
    s = sanitize(s)
    if len(s) % 2:
        s += "X"
    return [(A2I[s[i]], A2I[s[i + 1]]) for i in range(0, len(s), 2)]

def hill_enc(t, M):
    a, b, c, d = M
    out = []
    for x, y in pairs(t):
        out.append(I2A[(a * x + b * y) % 26] + I2A[(c * x + d * y) % 26])
    return "".join(out)

def hill_dec(t, M):
    IM = invM2(M)
    if IM is None:
        raise ValueError("Matrix not invertible")
    a, b, c, d = IM
    out = []
    for x, y in pairs(t):
        out.append(I2A[(a * x + b * y) % 26] + I2A[(c * x + d * y) % 26])
    return "".join(out)

# ---------------------------
# Vigenere
# ---------------------------
def vig_enc(t, k):
    t = sanitize(t)
    k = sanitize(k)
    return "".join(I2A[(A2I[t[i]] + A2I[k[i % len(k)]]) % 26] for i in range(len(t)))

def vig_dec(t, k):
    t = sanitize(t)
    k = sanitize(k)
    return "".join(I2A[(A2I[t[i]] - A2I[k[i % len(k)]]) % 26] for i in range(len(t)))

# ---------------------------
# Playfair
# ---------------------------
def pf_mat(key):
    key = sanitize(key).replace("J", "I")
    seq, seen = [], set()
    for c in key + ALPH.replace("J", ""):
        if c not in seen:
            seen.add(c)
            seq.append(c)
    return [seq[i:i + 5] for i in range(0, 25, 5)]

def pf_loc(M):
    loc = {}
    for i in range(5):
        for j in range(5):
            loc[M[i][j]] = (i, j)
    return loc

def pf_pairs(t):
    s = sanitize(t).replace("J", "I")
    out = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else "X"
        if a == b:
            out.append((a, "X"))
            i += 1
        else:
            out.append((a, b))
            i += 2
    if len(out[-1]) == 1:
        out[-1] = (out[-1][0], "X")
    return out

def pf_enc(t, k):
    M = pf_mat(k)
    L = pf_loc(M)
    out = []
    for a, b in pf_pairs(t):
        r1, c1 = L[a]
        r2, c2 = L[b]
        if r1 == r2:
            out.append(M[r1][(c1 + 1) % 5] + M[r2][(c2 + 1) % 5])
        elif c1 == c2:
            out.append(M[(r1 + 1) % 5][c1] + M[(r2 + 1) % 5][c2])
        else:
            out.append(M[r1][c2] + M[r2][c1])
    return "".join(out)

def pf_dec(t, k):
    M = pf_mat(k)
    L = pf_loc(M)
    out = []
    for a, b in pf_pairs(t):
        r1, c1 = L[a]
        r2, c2 = L[b]
        if r1 == r2:
            out.append(M[r1][(c1 - 1) % 5] + M[r2][(c2 - 1) % 5])
        elif c1 == c2:
            out.append(M[(r1 - 1) % 5][c1] + M[(r2 - 1) % 5][c2])
        else:
            out.append(M[r1][c2] + M[r2][c1])
    return "".join(out)

# ---------------------------
# Combined pipeline
# ---------------------------
def encrypt(p, H, V, P):
    return pf_enc(vig_enc(hill_enc(p, H), V), P)

def decrypt(c, H, V, P):
    return hill_dec(vig_dec(pf_dec(c, P), V), H)

# ---------------------------
# Known-plaintext attack
# ---------------------------
def invertibles():
    for a, b, c, d in itertools.product(range(26), repeat=4):
        if math.gcd(det2([a, b, c, d]), 26) == 1:
            yield [a, b, c, d]

def derive_vig_stream(kp, kc, M, P):
    inter = hill_enc(kp, M)
    dec_pf = pf_dec(kc, P)
    return "".join(I2A[(A2I[dec_pf[i]] - A2I[inter[i]]) % 26] for i in range(len(kp)))

def known_plain_attack(full_c, kp, kc, vlen, P, max_m=80000):
    best = (-1e9, None, None, None)
    cnt = 0
    for M in invertibles():
        cnt += 1
        if max_m and cnt > max_m:
            break
        ks = derive_vig_stream(kp, kc, M, P)
        vkey = "".join(ks[i % vlen] for i in range(vlen))
        try:
            p = decrypt(full_c, M, vkey, P)
        except Exception:
            continue
        score = sum(p.count(ch) for ch in "ETAOIN")
        if score > best[0]:
            best = (score, M, vkey, p)
        if cnt % 20000 == 0:
            print(f"[three-stage] Checked {cnt} matrices; best score {score}")
    return best, cnt

def experiment_three_stage(trials=3):
    banner("ATTACK / BREAK SIMULATION (THREE-STAGE)")
    for t in range(trials):
        plain = "THISPROJECTDEMONSTRATESHILLTHENVIGENERETHENPLAYFAIRCIPHER"[:200]
        H = [3, 3, 2, 5]
        V = "LONGSECRETK"
        P = "KEYWORD"
        c = encrypt(plain, H, V, P)
        kp = plain[:30]
        kc = c[:30]
        t0 = time.time()
        (sc, M, VK, p), n = known_plain_attack(c, kp, kc, len(V), P)
        t1 = time.time()
        ok = p.startswith(plain[:40])
        print(f"[Trial {t+1}] Time {t1 - t0:.2f}s | Tried {n} | Success={ok}")
    banner("ATTACK END")

# ---------------------------
# Main demo
# ---------------------------
if __name__ == "__main__":
    banner("THREE-STAGE CIPHER DEMO (HILL -> VIGENERE -> PLAYFAIR)")
    plain = "This demonstrates the three-stage classical cipher combination."
    plain = sanitize(plain)
    H = [3, 3, 2, 5]
    V = "LONGSECRETK"
    P = "KEYWORD"

    banner("ENCRYPTION")
    c = encrypt(plain, H, V, P)
    print("Plain:", plain[:80], "...")
    print("Cipher:", c[:80], "...")

    banner("DECRYPTION")
    d = decrypt(c, H, V, P)
    print("Decrypted equals plain?", d == plain)

    banner("FREQUENCY ANALYSIS")
    freq = Counter(c)
    print("Most common letters:", freq.most_common(8))

    experiment_three_stage()
