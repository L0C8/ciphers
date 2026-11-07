import io
import os
import sys
import zipfile
from itertools import cycle

KEY_LEN = 12
HERE   = os.path.dirname(os.path.abspath(__file__))
INPUT  = os.path.join(HERE, "XOR.zip.crypt")


def xor(data, key):
    return bytes(d ^ k for d, k in zip(data, cycle(key)))


def known_fragments(n):
    eocd = n - 22
    return [
        (0,          b"PK\x03\x04"),           # local file header signature
        (eocd,       b"PK\x05\x06"),           # EOCD signature
        (eocd + 4,   b"\x00\x00\x00\x00"),     # disk numbers (always 0 for single-disk)
        (eocd + 20,  b"\x00\x00"),             # comment length (0 = no comment)
    ]


def recover_key(cipher):
    key = [None] * KEY_LEN
    for offset, plain in known_fragments(len(cipher)):
        for i, p in enumerate(plain):
            pos  = offset + i
            # XOR of cipher byte and known plain byte gives us that key byte
            k = cipher[pos] ^ p
            # the key repeats every KEY_LEN bytes
            slot = pos % KEY_LEN
            if key[slot] is not None and key[slot] != k:
                sys.exit(f"conflict at key byte {slot}: {key[slot]:02x} vs {k:02x}")
            key[slot] = k
            print(f"  offset {pos:3d}  plain {p:02x}  cipher {cipher[pos]:02x}  -> key[{slot:2d}] = {k:02x}")
    return key


def main():
    with open(INPUT, "rb") as f:
        cipher = f.read()
    print(f"{INPUT}: {len(cipher)} bytes, key length {KEY_LEN}\n")

    # use known zip structure bytes to recover key bytes one at a time
    print("known plaintext from the zip format:")
    partial = recover_key(cipher)
    print("\npartial key: " + " ".join("??" if k is None else f"{k:02x}" for k in partial))

    # fill any unrecovered key bytes with 0x00 and attempt decryption
    key = bytes(k or 0 for k in partial)
    plain = xor(cipher, key)
    if None in partial:
        # not every key position was covered by the known fragments
        print("not all key bytes known yet - decryption with 00 for missing bytes:")
        print(plain[:64])
        sys.exit(1)

    # verify the decrypted result is actually a valid zip 
    try:
        archive = zipfile.ZipFile(io.BytesIO(plain))
        bad = archive.testzip()
    except zipfile.BadZipFile as e:
        sys.exit(f"decryption is not a valid zip: {e}")
    if bad:
        sys.exit(f"CRC check failed for {bad}")

    # save the key and the decrypted zip
    with open(os.path.join(HERE, "XOR.key"), "w") as f:
        f.write(key.hex())
    with open(os.path.join(HERE, "XOR.zip"), "wb") as f:
        f.write(plain)

    print(f"\nkey: {key.hex()}  -> XOR.key")
    print("decrypted zip is valid, all CRC-32 checks passed -> XOR.zip\n")

    # extract every file from the zip and print its contents
    out_dir = os.path.join(HERE, "XOR_extracted")
    os.makedirs(out_dir, exist_ok=True)
    for info in archive.infolist():
        data = archive.read(info)
        with open(os.path.join(out_dir, os.path.basename(info.filename)), "wb") as f:
            f.write(data)
        print(f"--- {info.filename} ({info.file_size} bytes) -> XOR_extracted/")
        print(data.decode(errors="replace"))


if __name__ == "__main__":
    main()
