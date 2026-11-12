#!/usr/bin/env python3
"""Build a hashed breach index from a password list and embed it in phishshield.html.

Usage:
  python build_breach_index.py rockyou.txt phishshield.html [--top 2000000] [--label rockyou.txt]

How it works:
  * Each password is hashed with SHA-256 and added to a Bloom filter (10 hash positions).
  * Only the filter bits are written to the page; the plaintext list is never published
    and cannot be read back from the index.
  * The browser hashes the typed password locally and tests the same bit positions.
  * rockyou.txt is ordered by frequency, so --top keeps the most common entries and
    keeps the page small (2,000,000 entries is about 4.8 MB, false-positive rate about 0.1%).
A "not found" result never proves a password is safe; it only means it is not in the list.
"""
import argparse, base64, hashlib, json, re, struct, sys

K = 10          # hash positions per password (must match the page: BD.k)
BITS_PER = 14.4  # bits per entry -> about 0.1% false positives


def read_words(path, top):
    seen, words = set(), []
    with open(path, 'rb') as f:
        for line in f:
            w = line.rstrip(b'\r\n')
            if not w:
                continue
            try:
                w.decode('utf-8')
            except UnicodeDecodeError:
                w = w.decode('latin-1').encode('utf-8')  # browsers send UTF-8
            if w in seen:
                continue
            seen.add(w)
            words.append(w)
            if len(words) >= top:
                break
    return words


def build(words):
    n = len(words)
    m = max(256, int(n * BITS_PER))
    bits = bytearray((m + 7) // 8)
    for w in words:
        h1, h2 = struct.unpack('>II', hashlib.sha256(w).digest()[:8])
        for i in range(K):
            p = (h1 + i * h2) % m
            bits[p >> 3] |= 1 << (p & 7)
    return n, m, bits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('wordlist')
    ap.add_argument('html')
    ap.add_argument('--top', type=int, default=2_000_000)
    ap.add_argument('--label', default='rockyou.txt')
    a = ap.parse_args()

    words = read_words(a.wordlist, a.top)
    if not words:
        sys.exit('The word list is empty. Check that the file uploaded correctly.')
    n, m, bits = build(words)
    block = json.dumps({'src': a.label, 'n': n, 'm': m, 'k': K,
                        'b64': base64.b64encode(bytes(bits)).decode()}, separators=(',', ':'))
    html = open(a.html, encoding='utf-8').read()
    pat = re.compile(r'(<script id="breach-data" type="application/json">).*?(</script>)', re.S)
    if not pat.search(html):
        sys.exit('breach-data block not found in the HTML file.')
    open(a.html, 'w', encoding='utf-8').write(pat.sub(lambda mo: mo.group(1) + block + mo.group(2), html, count=1))
    size = len(block) / 1_048_576
    print(f'Indexed {n:,} passwords, {m:,} bits, page data {size:.1f} MB')
    if size > 12:
        print('Warning: published pages must stay under 16 MB. Use a smaller --top value.')


if __name__ == '__main__':
    main()
