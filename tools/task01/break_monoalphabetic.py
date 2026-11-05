import os
import random
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)
from ngram_score import ngram_score

INPUT_FILE  = os.path.join(HERE, "Subst.txt")
OUTPUT_TEXT = os.path.join(HERE, "Plain.txt")
OUTPUT_KEY  = os.path.join(HERE, "subst.key")
QUADGRAMS   = os.path.join(HERE, "english_quadgrams.txt")

ALPHABET      = string.ascii_uppercase
ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
MAX_FAILS     = 2000
RESTARTS      = 5
VERBOSE       = False


def only_letters(text):
    return "".join(c for c in text.upper() if c in ALPHABET)


def decrypt(text, key):
    return text.translate(str.maketrans(key, ALPHABET))


def init_key(cipher):
    letters = only_letters(cipher)
    by_freq = sorted(ALPHABET, key=lambda c: -letters.count(c))
    key = [""] * 26
    for plain, cipher_letter in zip(ENGLISH_ORDER, by_freq):
        key[ALPHABET.index(plain)] = cipher_letter
    return "".join(key)


def swap_letters(key):
    i, j = random.sample(range(26), 2)
    key = list(key)
    key[i], key[j] = key[j], key[i]
    return "".join(key)


def climb(letters, start_key, scorer):
    key = start_key
    best = scorer.score(decrypt(letters, key))
    fails = 0
    while fails < MAX_FAILS:
        candidate = swap_letters(key)
        score = scorer.score(decrypt(letters, candidate))
        if score > best:
            if VERBOSE:
                swapped = [(a, b) for a, b in zip(key, candidate) if a != b]
                if len(swapped) == 2:
                    print(f"    swap {swapped[0][0]}<->{swapped[1][0]}  score {score:9.1f}  key {candidate}")
            key, best, fails = candidate, score, 0
        else:
            fails += 1
    return key, best


def hill_climb(cipher, scorer):
    letters = only_letters(cipher)
    starts = [init_key(cipher)] + ["".join(random.sample(ALPHABET, 26)) for _ in range(RESTARTS)]
    results = []
    for n, start in enumerate(starts):
        key, score = climb(letters, start, scorer)
        label = "frequency key" if n == 0 else f"random key {n}"
        print(f"  {label:<16} -> {key}  score {score:9.1f}")
        results.append((score, key))
    return max(results)


def main():
    with open(INPUT_FILE) as f:
        cipher = f.read()

    scorer = ngram_score(QUADGRAMS)
    start = init_key(cipher)

    print(f"file          : {INPUT_FILE}")
    print(f"letters       : {len(only_letters(cipher))}")
    print(f"starting key  : {ENGLISH_ORDER}")
    print(f"frequency key : {start}")
    print(f"  -> {decrypt(cipher, start)[:70]!r}")
    print("\nHill Climbing:")

    score, key = hill_climb(cipher, scorer)

    plain = decrypt(cipher, key)
    with open(OUTPUT_KEY, "w") as f:
        f.write(key)
    with open(OUTPUT_TEXT, "w") as f:
        f.write(plain)

    print(f"\nbest key  : {key}")
    print(f"saved     : {OUTPUT_KEY}")
    print(f"saved     : {OUTPUT_TEXT}\n")
    print(plain[:400])


if __name__ == "__main__":
    main()
