import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

INPUT_CIPHER = os.path.join(HERE, "cipher.crypt")
INPUT_P1     = os.path.join(HERE, "plaintext1.txt")
INPUT_P2     = os.path.join(HERE, "plaintext2.txt")
OUTPUT_K1    = os.path.join(HERE, "k1.key")
OUTPUT_K2    = os.path.join(HERE, "k2.key")


def load(path):
    with open(path, "rb") as f:
        return f.read()


def xor(a, b):
    result = bytearray(len(a))
    for i in range(len(a)):
        result[i] = a[i] ^ b[i]
    return bytes(result)


def verify(cipher, key, plaintext):
    decrypted = xor(cipher, key)
    return decrypted == plaintext


def save(path, data):
    with open(path, "wb") as f:
        f.write(data)


def show(name, key, cipher, plaintext):
    print(f"\n{name}: {key.hex()}")
    print(f"decrypted : {xor(cipher, key)!r}")
    print(f"verified  : {verify(cipher, key, plaintext)}\n")


def main():
    try:
        c  = load(INPUT_CIPHER)
        p1 = load(INPUT_P1)
        p2 = load(INPUT_P2)
    except OSError as e:
        sys.exit(f"error: {e}")

    print(f"cipher     : {INPUT_CIPHER}  ({len(c)} bytes)")
    print(f"plaintext1 : {INPUT_P1}  ({len(p1)} bytes)")
    print(f"plaintext2 : {INPUT_P2}  ({len(p2)} bytes)")

    if not len(c) == len(p1) == len(p2):
        sys.exit("error: all three files must be the same length for a one-time pad")

    k1 = xor(c, p1)
    k2 = xor(c, p2)

    show("k1.key", k1, c, p1)
    show("k2.key", k2, c, p2)

    save(OUTPUT_K1, k1)
    save(OUTPUT_K2, k2)

    print(f"saved : {OUTPUT_K1}")
    print(f"saved : {OUTPUT_K2}")


if __name__ == "__main__":
    main()
