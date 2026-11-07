# Task 1: Ciphertext-only Analysis

`Subst-Rijndael.crypt` was encrypted twice: first with a monoalphabetic substitution, then with AES in CBC mode. We remove the two layers in reverse order.

## 1.1 Brute-force Weak AES

**AES key (`aes.key`):** `c73f0000000000000000000000000000`

**The weakness.** AES itself was not broken. Only the first 16 of the 128 key bits were chosen and the rest are zeros, so there are only 2^16 = 65,536 possible keys. We simply try all of them.

**Recognizing the right key.** A wrong key does not cause an error, it just produces random-looking bytes. The correct result is still substitution-encrypted, so we cannot search it for English words. Instead we use Shannon entropy, which measures how evenly the byte values are spread:

- A wrong key gives random bytes that use all 256 values about equally: entropy = 7.9 bits.
- The right key gives text from a small alphabet (letters, spaces, punctuation): entropy = 4.2 bits.

A substitution only renames characters and does not change how often they appear, so it does not change the entropy. The script keeps the 10 lowest-entropy results in a heap, which shows the gap between the best key and the rest:

| Rank | Key                                |Entropy|
|------|------------------------------------|-------|
| 1    | `c73f0000000000000000000000000000` | 4.240 |
| 2    | `b09f0000000000000000000000000000` | 7.858 |
| 3    | `860f0000000000000000000000000000` | 7.862 |

The decryption is saved to `Subst.txt` as the input for 1.2.

```
python3 bruteforce_aes.py
```

## 1.2 Hill Climbing against the Monoalphabetic Substitution

**Substitution key (`subst.key`):** `BRFOLZUKPHDWMQACJGYTSINVEX` (plain A -> B, B -> R, …)

**The weakness.** 26! = 4·10^26 keys are too many to try, but a substitution keeps the statistics of the language: letters and letter combinations are only renamed.

**Why not just frequency analysis.** Mapping the most common cipher letter to E, the next to T, and so on only got 5 of 26 letters right on our text. The text is short (1,565 letters) and several letters have almost equal counts. Single-letter counts also cannot see context, so they cannot get any further.

**Hill climbing** answers the three questions from the lab sheet:

1. **Initialization key:** the frequency key above. It gets the most common letters (E, T) right and puts the climb on the right "hill".
2. **Next key:** swap two random letters in the key. A swap always gives a valid permutation, keeps the other 24 mappings, and any key can be reached by swaps.
3. **Quality:** the provided `ngram_score.py`. It adds up the log probabilities of every quadgram (4-letter sequence) in the decryption, based on English quadgram counts. More English-like text scores higher. Logarithms are used because multiplying ~1,560 probabilities would round to 0.

A swap is kept only if the score improves. A climb stops after 2,000 swaps in a row without improvement. Since a climb can get stuck on a wrong key (a local maximum), the script runs 6 climbs, one from the frequency key and 5 from random keys, and keeps the best score. In our run, 5 of 6 climbs reached the same key with score −6,415.0; one got stuck at −9,042.6.

**Result.** The key decrypts to the preface of Kant's *Critique of Practical Reason* ("THIS WORK IS CALLED THE CRITIQUE OF PRACTICAL REASON …"). It is the encryption key the task asks for: T → T, H → K, I → P, S → Y turns THIS into TKPY, the first word of `Subst.txt`.

```
python3 break_monoalphabetic.py
```

## Conclusion

The two layers fail for different reasons. AES is strong, but a key with 16 unknown bits makes it weak. The substitution has a huge key space, but it leaks the structure of the language, which hill climbing uses to find the key in seconds.
