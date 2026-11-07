# Task 3: Partial Known-Plaintext Analysis

**Key (`XOR.key`):** `28f76ef1d61388c88673ee8c`
**Decrypted:** `XOR.zip`, containing `README.md`: "Well Done! You have successfully decrypted the zip file :-)"

## Approach

**1. The weakness.** The 96-bit (12-byte) key is repeated over the whole file: byte `i` is XORed with key byte `i mod 12`. If we know a plaintext byte `p` and its ciphertext byte `c`, the key byte is `k = c ⊕ p`, and because the key repeats, that byte is valid at every 12th position. So we only need one known plaintext byte per key position.

note, this is identical to core logic of Vigenere cipher 

**2. Known plaintext from the zip format.** We don't know the contents, but every zip has fixed bytes:

| Position| Bytes         | Why we know it                               |
|---------|---------------|----------------------------------------------|
| 0       | `50 4B 03 04` | Every zip starts with this signature         |
| n − 22  | `50 4B 05 06` | End of Central Directory (EOCD) signature    |
| n − 18  | `00 00 00 00` | Disk numbers, 0 for a normal zip             |
| n − 2   | `00 00`       | Comment length, 0 (no comment)               |
|------------------------------------------------------------------------|

Because the zip has no comment, the EOCD record is exactly the last 22 bytes of the file.

**3. Recovering the key.** For each of these 14 bytes, `k = c ⊕ p` goes to key position `position mod 12`. Our file is 229 bytes (229 mod 12 = 1), so the end bytes cover key positions 3–11 and 0, and the signature at the start covers positions 0–3. Together that is all 12 key bytes. Positions 0 and 3 were each found twice and gave the same value both times, which already suggests the key is correct.

If key bytes had been missing, the script would fill them with `00`, decrypt, and show the partly readable result, so more plaintext (such as the file name at byte 30) could be guessed.

**4. Checking the key.** The script decrypts the file, opens it as a zip and tests every CRC-32 checksum. All pass. A wrong key would not: flipping a single bit of the key made the result unreadable as a zip.

## Running it

```
python3 XOR_decrypter.py
```

The script expects `XOR.zip.crypt` in the same folder and saves `XOR.key`, `XOR.zip` and the extracted files in `XOR_extracted/`.

## Conclusion

A short repeating XOR key leaks itself through any part of the file that can be predicted. 14 bytes of standard zip structure were enough to recover the full 96-bit key without knowing anything about the file's contents.
