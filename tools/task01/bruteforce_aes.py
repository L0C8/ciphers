import heapq
import math
import os
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = os.path.dirname(os.path.abspath(__file__))

BITS = 16
INPUT_FILE  = os.path.join(HERE, "Subst-Rijndael.crypt")
OUTPUT_TEXT = os.path.join(HERE, "Subst.txt")
OUTPUT_KEY  = os.path.join(HERE, "aes.key")


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 2 * BITS or len(data) % BITS:
        raise ValueError("invalid input")
    return data


def make_key(n, bits):
    key = bytearray(BITS)
    for i in range(bits):
        if n & (1 << (bits - 1 - i)):
            key[i // 8] |= 1 << (7 - (i % 8))
    return bytes(key)


def decrypt_cbc(data, key):
    iv, body = data[:BITS], data[BITS:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(body) + decryptor.finalize()


def entropy(data):
    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    h = 0.0
    for c in counts:
        if c:
            h += c / n * math.log2(c / n)
    return -h


def search(data, bits, keep=10):
    heap = []
    for n in range(2 ** bits):
        key = make_key(n, bits)
        plain = decrypt_cbc(data, key)
        e = entropy(plain)
        if len(heap) < keep:
            heapq.heappush(heap, (-e, key, plain))
        elif e < -heap[0][0]:
            heapq.heapreplace(heap, (-e, key, plain))
    return sorted(((-e, key, plain) for e, key, plain in heap), key=lambda r: r[0])


def preview(plain, width=40):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in plain[:width])


def show(results, top=5):
    print(f"\n  {'rank':>4}  {'key (hex)':<32}  {'entropy':>7}  preview")
    for i, (score, key, plain) in enumerate(results[:top], 1):
        print(f"  {i:>4}  {key.hex():<32}  {score:>7.3f}  {preview(plain)}")


def main():
    try:
        data = load(INPUT_FILE)
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")

    print(f"file   : {INPUT_FILE}")
    print(f"size   : {len(data)} bytes = IV + {len(data) // BITS - 1} blocks")
    print(f"search : first {BITS} of {BITS * 8} key bits, 2^{BITS} = {2 ** BITS:,} keys\n")

    t0 = time.perf_counter()
    results = search(data, BITS)
    print(f"completed in {time.perf_counter() - t0:.2f}s")
    show(results)

    _, key, plain = results[0]
    print(f"\nbest key : {key.hex()}")

    with open(OUTPUT_TEXT, "wb") as f:
        f.write(plain)
    with open(OUTPUT_KEY, "w") as f:
        f.write(key.hex())
    print(f"saved  : {OUTPUT_TEXT}")
    print(f"saved  : {OUTPUT_KEY}")


if __name__ == "__main__":
    main()
