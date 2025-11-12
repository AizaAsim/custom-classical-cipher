import itertools
import math
import time
from collections import Counter

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPH)}
I2A = {i: c for i, c in enumerate(ALPH)}

# ---------------------
# Utilities
# ---------------------
def banner(title: str):
    print("\n" + "="*80)
    print(f"====================   {title.upper()}   ====================")
    print("="*80 + "\n")

def sanitize(s: str) -> str:
    return "".join([c for c in s.upper() if c.isalpha()])

def chunk_pairs(s: str):
    s = sanitize(s)
    if len(s) % 2: s += "X"
    return [(A2I[s[i]], A2I[s[i+1]]) for i in range(0, len(s), 2)]

# ---------------------
# Hill 2x2 (mod 26)
# ---------------------
def modinv(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def det2(mat):
    a, b, c, d = mat
    return (a * d - b * c) % 26

def inv_matrix2(mat):
    a, b, c, d = mat
    det = det2(mat)
    inv_det = modinv(det, 26)
    if inv_det is None:
        return None
    return [(d * inv_det) % 26, ((-b) * inv_det) % 26, ((-c) * inv_det) % 26, (a * inv_det) % 26]

def is_invertible2(mat):
    return math.gcd(det2(mat), 26) == 1

def hill_encrypt(plaintext: str, mat):
    pairs = chunk_pairs(plaintext)
    a, b, c, d = mat
    out = []
    for x, y in pairs:
        r0 = (a * x + b * y) % 26
        r1 = (c * x + d * y) % 26
        out.append(I2A[r0] + I2A[r1])
    return "".join(out)

def hill_decrypt(ciphertext: str, mat):
    inv = inv_matrix2(mat)
    if inv is None:
        raise ValueError("Matrix not invertible")
    a, b, c, d = inv
    pairs = chunk_pairs(ciphertext)
    out = []
    for x, y in pairs:
        r0 = (a * x + b * y) % 26
        r1 = (c * x + d * y) % 26
        out.append(I2A[r0] + I2A[r1])
    return "".join(out)

# ---------------------
# Vigenere
# ---------------------
def vigenere_encrypt(plain: str, key: str):
    p = sanitize(plain)
    k = sanitize(key)
    out = []
    for i, ch in enumerate(p):
        out.append(I2A[(A2I[ch] + A2I[k[i % len(k)]]) % 26])
    return "".join(out)

def vigenere_decrypt(cipher: str, key: str):
    c = sanitize(cipher)
    k = sanitize(key)
    out = []
    for i, ch in enumerate(c):
        out.append(I2A[(A2I[ch] - A2I[k[i % len(k)]]) % 26])
    return "".join(out)

# ---------------------
# Combined pipeline
# ---------------------
def encrypt(plain: str, hill_mat, vig_key: str):
    return vigenere_encrypt(hill_encrypt(plain, hill_mat), vig_key)

def decrypt(cipher: str, hill_mat, vig_key: str):
    return hill_decrypt(vigenere_decrypt(cipher, vig_key), hill_mat)

# ---------------------
# Frequency analysis helpers
# ---------------------
ENGLISH_FREQ = {'E':12.7,'T':9.1,'A':8.2,'O':7.5,'I':7.0,'N':6.7,'S':6.3,'H':6.1,'R':6.0}

def english_score(text: str) -> float:
    if not text: return -1e9
    c = Counter(text)
    N = len(text)
    s = 0
    for k,v in ENGLISH_FREQ.items():
        s -= ((c[k]/N*100 - v)**2)/v
    return s

# ---------------------
# Known-plaintext attack
# ---------------------
def all_invertible_matrices():
    for a,b,c,d in itertools.product(range(26), repeat=4):
        m = [a,b,c,d]
        if is_invertible2(m):
            yield m

def derive_vig_keystream(kp,kc,M):
    inter = hill_encrypt(kp,M)
    return "".join(I2A[(A2I[kc[i]] - A2I[inter[i]])%26] for i in range(len(kp)))

def known_plaintext_attack(full_c,kp,kc,vlen=10,max_m=60000):
    full_c = sanitize(full_c); kp = sanitize(kp); kc = sanitize(kc)
    best=(-1e9,None,None,None);count=0
    for M in all_invertible_matrices():
        count+=1
        if max_m and count>max_m:break
        ks = derive_vig_keystream(kp,kc,M)
        vkey = "".join(ks[i%vlen] for i in range(vlen))
        try:p = decrypt(full_c,M,vkey)
        except:continue
        sc=english_score(p)
        if sc>best[0]: best=(sc,M,vkey,p)
        if count%20000==0: print(f"[two-stage] Checked {count} matrices; best score {sc:.2f}")
    return best,count

# ---------------------
# Experiment harness
# ---------------------
def experiment_two_stage(trials=3,text_len=300,known_len=30,max_matrices=120000):
    banner("ATTACK / BREAK SIMULATION (TWO-STAGE)")
    for t in range(trials):
        plain=("THISISASAMPLEPLAINTEXTUSEDFORTHECRYPTOASSIGNMENT"*10)[:text_len]
        H=[3,3,2,5];K="LONGSECRETK"
        c=encrypt(plain,H,K)
        kp=plain[:known_len];kc=c[:known_len]
        t0=time.time()
        (sc,M,V,p),tried=known_plaintext_attack(c,kp,kc,len(K),max_matrices)
        t1=time.time()
        ok=p.startswith(plain[:40])
        print(f"[Trial {t+1}] Time {t1-t0:.2f}s | Tried {tried} | Success={ok}")
    banner("ATTACK END")

# ---------------------
# CLI demo
# ---------------------
if __name__=="__main__":
    banner("TWO-STAGE CIPHER DEMO (HILL -> VIGENERE)")
    plain=input("Enter plaintext to encrypt (you may include spaces): ")
    plain=sanitize(plain)
    H=[3,3,2,5];K="LONGSECRETK"

    banner("ENCRYPTION")
    start_enc=time.time()
    c=encrypt(plain,H,K)
    end_enc=time.time()
    print("Plain:",plain)
    print("Cipher:",c)
    print(f"Encryption time: {(end_enc-start_enc)*1000:.2f} ms")

    banner("DECRYPTION")
    start_dec=time.time()
    d=decrypt(c,H,K)
    end_dec=time.time()
    print("Decrypted:",d)
    print("Matches sanitized plaintext?",d==plain)
    print(f"Decryption time: {(end_dec-start_dec)*1000:.2f} ms")

    banner("FREQUENCY ANALYSIS")
    freq=Counter(c)
    print("Top cipher letters:",freq.most_common(8))

    experiment_two_stage()

    # ---------------------------
    # Time Complexity & Efficiency Comparison
    # ---------------------------
    banner("TIME COMPLEXITY & EFFICIENCY ANALYSIS")
    print("Encryption Complexity:  O(n)  — linear in message length (Hill + Vigenere).")
    print("Decryption Complexity:  O(n)  — same as encryption, sequential linear passes.")
    print("Attack Complexity:      O(26^4 * n)  — brute force over invertible 2x2 matrices (~456k).")
    print("Comparison with Shift Cipher:")
    print("  - Shift cipher: O(n) but trivial keyspace (26 possibilities).")
    print("  - This two-stage cipher: O(2n) due to two layers, far stronger keyspace and diffusion.")
    print("  - Trade-off: Slightly slower, exponentially more secure.\n")
