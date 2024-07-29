import string
import numpy

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

with open("./hacker-manifesto.enc") as f:
    ciphertexts = list(map(lambda x: bytes.fromhex(x.strip()), f.readlines()))

longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
print(len(longest_c))

shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print(len(shortest_c))


candidates_list = []
for pos in range(max_len):
    freqs = numpy.zeros(256, dtype=float)
    for b in range(256):
        for ct in ciphertexts:
            if pos >= len(ct):
                continue
            if chr(ct[pos] ^ b) in string.printable:
                freqs[b] += CHARACTER_FREQ.get(chr(ct[pos] ^ b).lower(), 0)
    
    match_list = [(freqs[i], i) for i in range(256)]
    ordered_match_list = sorted(match_list, reverse=True)
    candidates = []
    max_matches = max(freqs)
    for pair in ordered_match_list:
        if pair[0] < max_matches * .80:
            break
        candidates.append(pair)
    
    candidates_list.append(candidates)

keystream = bytearray()

for candidates in candidates_list:
    keystream.append(candidates[0][1])

keystream[0] = keystream[0] ^ ord('E') ^ ord('T')
keystream[1] = keystream[1] ^ ord(' ') ^ ord('e')
keystream[2] = keystream[2] ^ ord('-') ^ ord('a')
keystream[3] = keystream[3] ^ ord(':') ^ ord('s')
keystream[5] = keystream[5] ^ ord(' ') ^ ord('i')
keystream[17] = keystream[17] ^ ord('<') ^ ord('s')
keystream[20] = keystream[20] ^ ord(' ') ^ ord('d')
keystream[28] = keystream[28] ^ ord('E') ^ ord('Y')
keystream[38] = keystream[38] ^ ord(' ') ^ ord('e')
keystream[40] = keystream[40] ^ ord('s') ^ ord('e')
keystream[42] = keystream[42] ^ ord('u') ^ ord('e')
keystream[43] = keystream[43] ^ ord('n') ^ ord('c')
keystream[45] = keystream[45] ^ ord("\'") ^ ord('u')
keystream[46] = keystream[46] ^ ord(" ") ^ ord('t')
keystream[49] = keystream[49] ^ ord(' ') ^ ord('a')
keystream[53] = keystream[53] ^ ord('_') ^ ord('t')
#keystream[57] = keystream[57] ^ ord('O') ^ ord('t')
keystream[58] = keystream[58] ^ ord('0') ^ ord('i')
keystream[59] = keystream[59] ^ ord('\'') ^ ord('n')
#keystream[63] = keystream[63] ^ ord(',') ^ ord(';')
keystream[65] = keystream[65] ^ ord('S') ^ ord('t')
keystream[67] = keystream[67] ^ ord('1') ^ ord('t')
keystream[69] = keystream[69] ^ ord('Y') ^ ord('s')




for ct in ciphertexts:
    plaintext = bytearray()
    for k, c in zip(keystream, ct):
        plaintext.append(k ^ c)
    print(plaintext)