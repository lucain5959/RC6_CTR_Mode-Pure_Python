import struct
import time
from math import ceil
import hashlib
import base64
import secrets

#not memory safe, constant time, etc. do not use on public computers

#Define helper functions for RC6
# rotate right input x, by n bits
def ROR(x, n, bits=32):
    mask = (2 ** n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


# rotate left input x, by n bits
def ROL(x, n, bits=32):
    return ROR(x, bits - n, bits)


def bytesToWord(bytes):
    return list(struct.unpack('<' + str(len(bytes) // 4) + 'i', bytes))

def wordsToBytes(words):
    return struct.pack('<' + str(len(words)) + 'L', *words)


def generateKey(userkey):
    r = 20
    t = 2*r+4
    w = 32
    modulo = 2 ** w
    encoded = bytesToWord(userkey)
    enlength = len(encoded)

    s = t * [0]
    s[0] = 0xB7E15163
    for i in range(1, t):
        s[i] = (s[i - 1] + 0x9E3779B9) % (2 ** w)

    v = 3 * max(enlength, t)
    A = B = i = j = 0

    for index in range(0, v):
        A = s[i] = ROL((s[i] + A + B) % modulo, 3, 32)
        B = encoded[j] = ROL((encoded[j] + A + B) % modulo, (A + B) % 32, 32)
        i = (i + 1) % t
        j = (j + 1) % enlength
    return s

def encryptblock(sentence, s):
    cipher = bytesToWord(sentence)
    A = cipher[0]
    B = cipher[1]
    C = cipher[2]
    D = cipher[3]

    r = 20
    w = 32
    modulo = 2 ** w
    lgw = 5
    B = (B + s[0]) % modulo
    D = (D + s[1]) % modulo
    for i in range(1, r + 1):
        t_temp = (B * (2 * B + 1)) % modulo
        t = ROL(t_temp, lgw, 32)
        u_temp = (D * (2 * D + 1)) % modulo
        u = ROL(u_temp, lgw, 32)
        tmod = t % 32
        umod = u % 32
        A = (ROL(A ^ t, umod, 32) + s[2 * i]) % modulo
        C = (ROL(C ^ u, tmod, 32) + s[2 * i + 1]) % modulo
        (A, B, C, D) = (B, C, D, A)
    A = (A + s[2 * r + 2]) % modulo
    C = (C + s[2 * r + 3]) % modulo
    cipher = [A, B, C, D]
    cipherbytes = wordsToBytes(cipher)
    return cipherbytes

#Encrypt Block at a time
def RC6Encrypt(data, key):
    s = generateKey(key)
    cipher = encryptblock(data, s)
    return cipher

#Encrypt iterating counter in multiple blocks. Note: There is no nonce, each key is different due to salt appended
def rc6countermode(key, length = 16):
        hash_len = 16
        newkey = generateKey(key)
        length = int(length)
        t = b""
        okm = b""
        for i in range(ceil(length / hash_len)):
            counter = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            nonceinteger = int.from_bytes(counter, 'big')
            nonceinteger += i
            iteratednonce = (nonceinteger).to_bytes(16, byteorder='big')
            t = bytearray(RC6Encrypt(iteratednonce, key))
            okm += t
        return bytearray(okm[:length])

#XOR stream to plainext
def rc6encrypt (key, plaintext):
    stream = bytearray(rc6countermode(key, length=(len(plaintext))))
    return bytearray(x^y for x, y in zip(plaintext, stream))



print ("Input plaintext:")
plaintext = bytearray(input().encode())
print ("Input password:")
password = bytearray(input().encode())
timed = time.time()
salt = bytearray(secrets.token_bytes(32))
key = bytearray(hashlib.pbkdf2_hmac('sha512', password, salt, 500000, dklen=32))
ciphertext = bytearray(rc6encrypt(key, plaintext))

print ("Elapsed Time:", time.time()-timed)
print ("Encrypted Text:", base64.b64encode(ciphertext+salt).decode('utf-8'))
