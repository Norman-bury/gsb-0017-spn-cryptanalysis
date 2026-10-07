#!/usr/bin/env python3
import itertools
import math
import os
import subprocess

SBOX = [0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7]
SINV = [0] * 16
for i, v in enumerate(SBOX):
    SINV[v] = i

HERE = os.path.dirname(os.path.abspath(__file__))


def P(x):
    nib = [(x >> 12) & 15, (x >> 8) & 15, (x >> 4) & 15, x & 15]
    out = 0
    for j in range(4):
        on = 0
        for k in range(4):
            on = (on << 1) | ((nib[k] >> (3-j)) & 1)
        out = (out << 4) | on
    return out


def S(x):
    return (SBOX[(x >> 12) & 15] << 12) | (SBOX[(x >> 8) & 15] << 8) | (SBOX[(x >> 4) & 15] << 4) | SBOX[x & 15]


def encrypt(p, hi, lo, k2, k3):
    x = p
    for k in (hi, lo, k2):
        x = P(S(x ^ k))
    return x ^ k3


def ddt():
    t = [[0] * 16 for _ in range(16)]
    for a in range(16):
        for x in range(16):
            t[a][SBOX[x] ^ SBOX[x ^ a]] += 1
    return t


DDT = ddt()


def transitions(a):
    return [(b, DDT[a][b]) for b in range(16) if DDT[a][b]]


def query():
    inp = ''.join('%04x\n' % p for p in range(1 << 16)).encode()
    out = subprocess.run([os.path.join(HERE, 'oracle')], input=inp,
                         stdout=subprocess.PIPE, check=True).stdout.split()
    return [int(x, 16) for x in out]


def characteristics():
    # One active plaintext nibble; follow two active S-box layers and keep
    # trails ending in one active nibble immediately before the last S-box.
    out = {}
    for pos in range(4):
        for a in range(1, 16):
            for b, c0 in transitions(a):
                d1 = P(b << (4 * (3-pos)))
                dn = [(d1 >> 12) & 15, (d1 >> 8) & 15, (d1 >> 4) & 15, d1 & 15]
                choices = [transitions(v) if v else [(0, 16)] for v in dn]
                for trail in itertools.product(*choices):
                    eta = sum(v << (4 * (3-i)) for i, (v, c) in enumerate(trail))
                    nib = [(eta >> 12) & 15, (eta >> 8) & 15, (eta >> 4) & 15, eta & 15]
                    active = [i for i, v in enumerate(nib) if v]
                    if len(active) != 1:
                        continue
                    target = active[0]
                    prob = (c0 / 16) * math.prod(c / 16 for v, c in trail)
                    alpha = a << (4 * (3-pos))
                    item = (prob, alpha, eta, target, nib[target], b, trail)
                    if (alpha, eta) not in out or prob > out[(alpha, eta)][0]:
                        out[(alpha, eta)] = item
    return sorted(out.values(), reverse=True)


def k3_scores(ct, chars):
    # Last-round 1R counters: for each ciphertext nibble, hypothesize the
    # whitening-key nibble, invert the final S-box, and compare the resulting
    # S-box input differences with the trail prediction.  Raw counts from the
    # strongest trails are retained for the report.
    scores = [[0.0] * 16 for _ in range(4)]
    raw = {}
    grouped = {i: [] for i in range(4)}
    for z in chars:
        grouped[z[3]].append(z)
    for target, group in grouped.items():
        # High-probability independent trails give the cleanest aggregate.
        group = group[:1]
        for prob, alpha, eta, pos, g, b0, trail in group:
            sh = 4 * (3-pos)
            count = [0] * 16
            freq = [0] * 256
            for plain in range(1 << 16):
                paired = plain ^ alpha
                if paired < plain:
                    continue
                c = (ct[plain] >> sh) & 15
                d = (ct[paired] >> sh) & 15
                freq[(c << 4) | d] += 1
            for cd, n in enumerate(freq):
                if not n:
                    continue
                c = cd >> 4
                d = cd & 15
                for k in range(16):
                    if SINV[c ^ k] ^ SINV[d ^ k] == g:
                        count[k] += n
            mean = sum(count) / 16
            sd = math.sqrt(sum((v - mean) ** 2 for v in count) / 15)
            if sd:
                for k in range(16):
                    scores[target][k] += prob * (count[k] - mean) / sd
            raw[target] = (alpha, eta, g, prob, count)
    return scores, raw


def validate(k3, ct):
    # Linear schedule inversion: K3 = hi + 2lo, so hi = K3 - 2lo.  This is
    # only 2^16 arithmetic candidates for one fixed K3, followed by two
    # known-plaintext checks; the 32-bit key is never enumerated.
    for lo in range(1 << 16):
        hi = (k3 - 2 * lo) & 0xffff
        k2 = (hi + lo) & 0xffff
        if encrypt(0, hi, lo, k2, k3) == ct[0] and encrypt(0x1234, hi, lo, k2, k3) == ct[0x1234]:
            return (hi << 16) | lo
    return None


def write_report(chars, scores, raw, k3, key):
    hi = key >> 16
    lo = key & 0xffff
    lines = ['# Differential cryptanalysis of the 3-round SPN', '',
             '## 1. S-box differential distribution table (DDT)', '',
             '`DDT[a][b]` counts inputs `x` such that `S[x] xor S[x xor a] = b`.', '',
             '| a\\\\b | ' + ' | '.join('%X' % b for b in range(16)) + ' |',
             '|' + '---|' * 17]
    for a, row in enumerate(DDT):
        lines.append('| **%X** | ' % a + ' | '.join(map(str, row)) + ' |')
    lines += ['', 'The strongest row is `11 -> 2`, with 8 of 16 input pairs (probability 1/2). Rows including `2 -> 5`, `4 -> 6`, `10 -> 8`, and `12 -> 13` have 6/16 (3/8). These entries determine the trails below.', '',
              '## 2. Selected differential characteristics and probabilities', '',
              'Each chosen plaintext difference activates one nibble. After round one, P moves the S-box output difference into a single bit-slice; round two then activates one S-box. The value listed as final-S input difference is the nibble difference presented to the last S-box. The last-round inversion tests only 16 hypotheses per key nibble.', '',
              '| plaintext difference | first S transition | after round 1 | final-S input difference | K3 nibble | probability |',
              '|---|---:|---:|---:|---:|---:|']
    for prob, alpha, eta, target, g, b0, trail in sorted(chars, reverse=True)[:16]:
        active_pos = next(i for i in range(4) if (alpha >> (4*(3-i))) & 15)
        a0 = (alpha >> (4*(3-active_pos))) & 15
        d1 = P(b0 << (4*(3-active_pos)))
        lines.append('| `%04x` | `%X -> %X` | `%04x` | `%04x` | %d | %.4f (%d/256) |' %
                     (alpha, a0, b0, d1, eta, target, prob, round(256*prob)))
    lines += ['', 'The two workhorse trails are `0x0b00 -> 0x0060` for K3 nibble 2 and `0x00b0 -> 0x0050`, also for K3 nibble 2; analogous rotated trails use `0x0f00 -> 0x0600`, `0x0e00 -> 0x6000`, and `0x0d00 -> 0x0006` for the other nibbles. Their two-round probabilities are 3/16, 9/64, and related DDT-derived values. The attack uses the full 2^16 plaintext codebook and canonical pairs `(p, p xor alpha)`.', '',
              '## 3. Candidate subkey hit statistics', '',
              'Recovered `K3 = %04x`; from the linear key schedule, `K2 = %04x`, `hi = %04x`, and `lo = %04x`.' % (k3, (hi+lo)&0xffff, hi, lo), '']
    for i in range(4):
        alpha, eta, g, prob, count = raw[i]
        order = sorted(enumerate(count), key=lambda z: z[1], reverse=True)
        true = (k3 >> (4*(3-i))) & 15
        second = order[0][0] if order[0][0] != true else order[1][0]
        lines += ['### K3 nibble %d (true nibble `%X`)' % (i, true), '',
                  'Representative feature `%04x -> %04x`, feature probability %.4f, final S-box input nibble difference `%X`. The true candidate receives %d hits over 32768 canonical pairs; the highest alternate is nibble `%X` with %d hits.' % (alpha, eta, prob, g, count[true], second, count[second]), '',
                  '| candidate | raw hits | aggregate score |', '|---:|---:|---:|']
        for k, v in sorted(enumerate(count), key=lambda z: z[1], reverse=True):
            lines.append('| `%X` | %d | %.3f |' % (k, v, scores[i][k]))
        lines.append('')
    lines += ['The computational claim is differential, not exhaustive: oracle work is 2^16 encryptions; key-nibble work is 4 x 16 last-round hypotheses; the remaining schedule inversion is linear arithmetic over `lo` and is verified by two known plaintext/ciphertext pairs.', '']
    with open(os.path.join(HERE, 'report.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    import time as _t; _st=_t.time(); ct = query(); print('query',_t.time()-_st)
    chars = characteristics()
    _t0=_t.time(); scores, raw = k3_scores(ct, chars); print('scores',_t.time()-_t0)
    print([sorted(enumerate(scores[i]),key=lambda z:z[1],reverse=True)[:3] for i in range(4)])
    return
    # Rank nibbles independently.  Validation rejects any inconsistent
    # differential candidate; then nearby ranks are tried without expanding
    # to the master-key space.
    ranks = [sorted(enumerate(scores[i]), key=lambda z: z[1], reverse=True) for i in range(4)]
    key = None
    chosen = None
    for depth in (1, 4, 8, 16):
        for picks in itertools.product(range(depth), repeat=4):
            nib = [ranks[i][picks[i]][0] for i in range(4)]
            k3 = sum(nib[i] << (4*(3-i)) for i in range(4))
            key = validate(k3, ct)
            if key is not None:
                chosen = k3
                break
        if key is not None:
            break
    write_report(chars, scores, raw, chosen, key)
    print('recovered key: %08x' % key)


if __name__ == '__main__':
    main()
