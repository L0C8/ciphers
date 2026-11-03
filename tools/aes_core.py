import heapq
import math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 2 * BLOCK or len(data) % BLOCK:
        raise ValueError("invalid input")
    return data

def make_key(n, bits):
    key = bytearray(BLOCK)
    for i in range(bits):
        if n & (1 << (bits - 1 - i)):
            key[i // 8] |= 1 << (7 - (i % 8))
    return bytes(key)


def decrypt_cbc(data, key):
    iv, body = data[:BLOCK], data[BLOCK:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(body) + decryptor.finalize()


def entropy(data):
    n = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return -sum(c / n * math.log2(c / n) for c in counts if c)


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
