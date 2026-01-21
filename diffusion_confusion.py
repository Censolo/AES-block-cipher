from random import randbytes, randrange
from aes import AES

def flip_bit(data, bit_index):
    if not (0 <= bit_index < len(data)*8):
        raise ValueError("bit_index out of range")
    byte_index, offset = divmod(bit_index, 8)   # outputs quotient and reminder of division
    flipped = data[byte_index] ^ (1 << (7-offset))    # (Big-endian) bit-flipping the offset bit
    return data[:byte_index] + bytes([flipped]) + data[byte_index+1:]    # inserting flipped byte in output

def hamming_distance(a, b):
    if len(a) != len(b):
        raise ValueError("Different Lenghts")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def aes_diffusion(num_rounds = None):   # 1 bit flip in plaintext, then check hamming distance
    key = randbytes(16)
    plain = randbytes(16)
    aes = AES(key)

    plain_flip = flip_bit(plain, randrange(128))

    c1 = aes.partially_encrypt(plain,        num_rounds)
    c2 = aes.partially_encrypt(plain_flip,   num_rounds)
    return hamming_distance(c1, c2)

def aes_confusion(num_rounds = None):   # 1 bit flip in key, then check hamming distance
    key      = randbytes(16)
    key_flip = flip_bit(key, randrange(128))
    plain    = randbytes(16)

    c1 = AES(key     ).partially_encrypt(plain, num_rounds)
    c2 = AES(key_flip).partially_encrypt(plain, num_rounds)
    return hamming_distance(c1, c2)