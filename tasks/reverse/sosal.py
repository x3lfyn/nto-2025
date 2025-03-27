from copy import deepcopy

def lrot(x, c):
    return ((x << c) & 0xff) | ((x >> (8-c)) & 0xff)


PBOX = [ 0xa2, 0xe0, 0xca, 0x64, 0xc3, 0xe5, 0x5b, 0xcf, 0xc6, 0xc7, 0x33, 0x99, 0x75, 0x9c, 0x35, 0x1c, 0x63, 0x94, 0x8e, 0x70, 0xa1, 0xbe, 0x41, 0xd5, 0xaa, 0xbd, 0x56, 0xda, 0x2c, 0x62, 0x97, 0x9a, 0x8d, 0x3f, 0xf6, 0xe7, 0x04, 0x50, 0xe8, 0xc4, 0x3c, 0x7c, 0xd3, 0x76, 0xa0, 0xc0, 0x6e, 0x85, 0x71, 0x16, 0x34, 0x1d, 0xbc, 0xf3, 0xed, 0x5f, 0xdd, 0xa5, 0xae, 0x21, 0x46, 0xfa, 0x1b, 0x07, 0x4d, 0xef, 0x5a, 0x78, 0xd6, 0x54, 0x67, 0x8c, 0xf2, 0xf0, 0xff, 0x81, 0x55, 0x59, 0xdc, 0xd1, 0xa8, 0x15, 0x01, 0x4c, 0x40, 0xd2, 0xf8, 0x38, 0x4f, 0x77, 0x8f, 0x61, 0xc1, 0x4a, 0xb6, 0x98, 0xc8, 0x6c, 0x19, 0x44, 0x84, 0x93, 0xe1, 0xab, 0x20, 0x32, 0x66, 0x91, 0x0c, 0x79, 0x57, 0xcb, 0xb3, 0x3b, 0x6d, 0x5e, 0x80, 0xf9, 0xa6, 0x73, 0x12, 0x31, 0xf1, 0xd8, 0x7e, 0xee, 0x87, 0xb9, 0x9d, 0xb0, 0x26, 0x69, 0xde, 0x92, 0x7f, 0x5d, 0x83, 0x13, 0x29, 0xfb, 0xd9, 0x22, 0x74, 0xbf, 0xb5, 0x9b, 0x45, 0xb4, 0x53, 0xf4, 0x23, 0xac, 0xe9, 0x65, 0x88, 0xf5, 0x1a, 0x28, 0x72, 0xc5, 0xfe, 0x06, 0x3d, 0xe6, 0xba, 0x37, 0x14, 0x36, 0x6f, 0x02, 0x11, 0x2b, 0xfd, 0x03, 0x8b, 0x1f, 0x5c, 0x68, 0xe4, 0xea, 0x47, 0x7a, 0x8a, 0x4e, 0xad, 0xf7, 0x58, 0x89, 0xe3, 0x60, 0xd0, 0x7b, 0x96, 0x2a, 0xb7, 0x00, 0x05, 0x0d, 0xfc, 0x49, 0x25, 0x2e, 0xb2, 0xaf, 0x51, 0x3e, 0x52, 0xcd, 0xeb, 0x42, 0x39, 0xd4, 0xc9, 0xa7, 0x7d, 0x82, 0x08, 0x09, 0xb8, 0x1e, 0x6b, 0xb1, 0xa3, 0x90, 0x9e, 0xe2, 0xdf, 0x24, 0x43, 0x6a, 0x0b, 0x27, 0x48, 0x10, 0x2f, 0x30, 0x17, 0xa9, 0x2d, 0x9f, 0x4b, 0xdb, 0xd7, 0x0f, 0xc2, 0xce, 0x3a, 0x95, 0x18, 0xec, 0x0e, 0xa4, 0x86, 0xbb, 0xcc, 0x0a ]
mask = [ 0x7b, 0xab, 0xad, 0x3e, 0xb1, 0x1b, 0x58, 0x99, 0xdb, 0x52, 0x56, 0x1f, 0xa2, 0x81, 0xd3, 0x76 ]

def decryptBlock(block, key, startOffset, bs):
    block = deepcopy(block)
    key = deepcopy(key)
    for i in range(startOffset, startOffset + bs):
        block[i] = lrot(block[i], 5)
    for r in range(25):
        for i in range(startOffset, startOffset + bs):
            block[i] = lrot(block[i] ^ key[i], 3)
            key[i] = PBOX[key[i]]
    for i in range(startOffset, startOffset + bs):
        block[i] ^= mask[i]
    for i in range(startOffset, startOffset + bs):
        block[i] = lrot(block[i], 5)
    return block

key = [0x49,0x3a,0xc7,0x26,0xa8,0xc6,0x9e,0x21,0x0e,0x9b,0x5b,0x49,0x23,0xb2,0x79,0x0c]

ctFlag = [0x27,0x0a,0x46,0x55,0x5c,0x80,0xba,0x99,0x80,0xe4,0x9e,0x51,0x74,0x14,0x04,0xfb]
ctFlag1 = [0x4e,0x13,0x37,0x95,0x04,0x33,0x59,0x69,0x21,0xac,0xf6,0x59,0x9c,0x84,0xd4,0xa9]
ctFlag2 = [0xef,0xe9,0xa7,0x07,0xe5,0xda,0xb0,0xfb,0xd2,0x5d,0x85,0x9a,0x67,0xa7,0x1f,0x0a]

import itertools, string
e = enumerate
rainbow = {}

for offset in range(16):
    for ct in range(256):
        meow = []
        for k in range(256):
            c = [0] * offset + [ct] + [0] * (15 - offset)
            key = [0] * offset + [k] + [0] * (15 - offset)
            res = decryptBlock(c, key, 0, 16)
            meow.append(res[offset])
        rainbow[(offset, ct)] = meow
print("crazy precompute completed")

ctFull = ctFlag + ctFlag1 + ctFlag2

offsets = []
for offset in range(len(ctFull) - 5):
    block = ctFull[offset:offset+5]
    flag = True
    for block_index,(c, p) in enumerate(zip(block, b':nto{')):
        if p not in rainbow[( 
            (offset + block_index) % 16,
            c
        )]:
            flag = False
            break
    if flag:
        print("Posssibly at offset", offset)
        offsets.append(offset)

keys = [[[], [], [], [], []] for i in range(6)]

for off_index, off in enumerate(offsets):
    block = ctFull[off:off + 5]
    for i,(p, c) in enumerate(zip(b':nto{', block)):
        vals = rainbow[(
            (off + i) % 16,
            c
        )]
        for j,v in enumerate(vals):
            if v == p:
                keys[off_index][i].append(j)

print("Generated key sets:")
print(*keys, sep='\n')

normalized_keys = []

for off_index,off in e(offsets):
    print("Trying offset", off)
    keyset = keys[off_index]
    for key in itertools.product(*keyset):
        kk = [0] * len(ctFull)
        for i in range(off, off + 5):
            kk[i] = key[i - off]
        key = list(map(
            lambda i: kk[i] + kk[16 + i] + kk[32 + i],
            range(16)
        ))
        normalized_keys.append((key, off_index))
        print(key)

from copy import deepcopy

for key in normalized_keys:
    plaintext = decryptBlock(ctFlag, key[0], 0, 16) + decryptBlock(ctFlag1, key[0], 0, 16) + decryptBlock(ctFlag2, key[0], 0, 16)
    res = b''
    for i,v in e(plaintext):
        if key[0][i % 16] == 0:
            res += b'.'
        else:
            res += bytes([v])
    print(res, key[0])

SELECTED_KEYSET = list(map(lambda x: x[0], filter(lambda x: x[1] == 1, normalized_keys)))

print('guessing')

SELECTED_KEYSET2 = []

for k1, k2 in itertools.product(range(256), repeat=2):
    for key in SELECTED_KEYSET:
        key = deepcopy(key)
        key[-1], key[-2] = k1, k2
        plaintext = decryptBlock(ctFlag, deepcopy(key), 0, 16) + decryptBlock(ctFlag1, deepcopy(key), 0, 16) + decryptBlock(ctFlag2, deepcopy(key), 0, 16)
        if plaintext[-1] != ord('\r') or plaintext[-2] != ord('\r'):
            continue
        SELECTED_KEYSET2.append(key)
        res = b''
        for i,v in e(plaintext):
            if key[i % 16] == 0:
                res += b'.'
            else:
                res += bytes([v])
        print(res, key)

SELECTED_KEYSET = [SELECTED_KEYSET2[0]]
SELECTED_KEYSET2 = []

print('guessing x2')

for k1, k2 in itertools.product(range(256), repeat=2):
    for key in SELECTED_KEYSET:
        key = deepcopy(key)
        key[-8], key[-9] = k1, k2
        plaintext = decryptBlock(ctFlag, deepcopy(key), 0, 16) + decryptBlock(ctFlag1, deepcopy(key), 0, 16) + decryptBlock(ctFlag2, deepcopy(key), 0, 16)
        if plaintext[-8] != ord('\r') or plaintext[-9] != ord('\r'):
            continue
        SELECTED_KEYSET2.append(key)
        res = b''
        for i,v in e(plaintext):
            if key[i % 16] == 0:
                res += b'.'
            else:
                res += bytes([v])
        print(res, key)

SELECTED_KEYSET = [SELECTED_KEYSET2[0]]
SELECTED_KEYSET2 = []

print('guessing x3')

for k1, k2 in itertools.product(range(256), repeat=2):
    for key in SELECTED_KEYSET:
        key = deepcopy(key)
        key[-10], key[-11] = k1, k2
        plaintext = decryptBlock(ctFlag, deepcopy(key), 0, 16) + decryptBlock(ctFlag1, deepcopy(key), 0, 16) + decryptBlock(ctFlag2, deepcopy(key), 0, 16)
        if plaintext[-10] != ord('\r') or plaintext[-11] != ord('\r'):
            continue
        SELECTED_KEYSET2.append(key)
        res = b''
        for i,v in e(plaintext):
            if key[i % 16] == 0:
                res += b'.'
            else:
                res += bytes([v])
        print(res, key)

SELECTED_KEYSET = [SELECTED_KEYSET2[0]]
SELECTED_KEYSET2 = []

print('guessing x4')

for k1, k2 in itertools.product(range(256), repeat=2):
    for key in SELECTED_KEYSET:
        key = deepcopy(key)
        key[-12], key[-13] = k1, k2
        plaintext = decryptBlock(ctFlag, deepcopy(key), 0, 16) + decryptBlock(ctFlag1, deepcopy(key), 0, 16) + decryptBlock(ctFlag2, deepcopy(key), 0, 16)
        if plaintext[-13] != ord('\r') or plaintext[-12] != ord('\r'):
            continue
        SELECTED_KEYSET2.append(key)
        res = b''
        for i,v in e(plaintext):
            if key[i % 16] == 0:
                res += b'.'
            else:
                res += bytes([v])
        print(res, key)

SELECTED_KEYSET = [SELECTED_KEYSET2[0]]
SELECTED_KEYSET2 = []

print('guessing x5')

for k1, k2 in itertools.product(range(256), repeat=2):
    for key in SELECTED_KEYSET:
        key = deepcopy(key)
        key[0], key[1] = k1, k2
        plaintext = decryptBlock(ctFlag, deepcopy(key), 0, 16) + decryptBlock(ctFlag1, deepcopy(key), 0, 16) + decryptBlock(ctFlag2, deepcopy(key), 0, 16)
        if plaintext[0] != ord('F') or plaintext[1] != ord('L'):
            continue
        SELECTED_KEYSET2.append(key)
        res = b''
        for i,v in e(plaintext):
            if key[i % 16] == 0:
                res += b'.'
            else:
                res += bytes([v])
        print(res, key)

SELECTED_KEYSET = [SELECTED_KEYSET2[0]]
SELECTED_KEYSET2 = []

print('guessing x6')

for k1 in itertools.product(range(256), repeat=1):
    for key in SELECTED_KEYSET:
        key = deepcopy(key)
        key[2] = k1[0]
        plaintext = decryptBlock(ctFlag, deepcopy(key), 0, 16) + decryptBlock(ctFlag1, deepcopy(key), 0, 16) + decryptBlock(ctFlag2, deepcopy(key), 0, 16)
        if plaintext[2] != ord('A'):
            continue
        SELECTED_KEYSET2.append(key)
        res = b''
        for i,v in e(plaintext):
            if key[i % 16] == 0:
                res += b'.'
            else:
                res += bytes([v])
        print(res, key)
