from aes import AES
from random import randbytes

class BlockCipher:
    def __init__(self, key, iv=None, algorithm=AES, mode='ECB'):
        self.key = key
        self.algorithm = algorithm(self.key)
        self.mode = mode.upper()
        self.iv = iv if iv else randbytes(16)  

    def pad(self, text):
        pad_len = 16 - (len(text) % 16)
        return text + bytes([pad_len] * pad_len)

    def unpad(self, padded_text):
        pad_len = padded_text[-1]
        return padded_text[:-pad_len]

    def encrypt(self, plaintext):
        plaintext = self.pad(plaintext)

        if self.mode == 'ECB':
            return b''.join(self.algorithm.encrypt(plaintext[i:i+16]) for i in range(0, len(plaintext), 16))

        elif self.mode == 'CBC':
            ciphertext = b''
            prev = list(self.iv)
            for i in range(0, len(plaintext), 16):
                block = list(plaintext[i:i+16])
                xored = AES.xor_bytes(block, prev)
                encrypted = self.algorithm.encrypt(bytes(xored))
                ciphertext += encrypted
                prev = list(encrypted)
            return ciphertext

        elif self.mode == 'CFB':
            ciphertext = b''
            prev = list(self.iv)
            for i in range(0, len(plaintext), 16):
                keystream = self.algorithm.encrypt(bytes(prev))
                block = list(plaintext[i:i+16])
                encrypted = AES.xor_bytes(block, list(keystream))
                ciphertext += bytes(encrypted)
                prev = encrypted
            return ciphertext

        elif self.mode == 'OFB':
            ciphertext = b''
            prev = list(self.iv)
            for i in range(0, len(plaintext), 16):
                prev = list(self.algorithm.encrypt(bytes(prev)))
                block = list(plaintext[i:i+16])
                encrypted = AES.xor_bytes(block, prev)
                ciphertext += bytes(encrypted)
            return ciphertext

        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def decrypt(self, ciphertext):


        if self.mode == 'ECB':
            plaintext = b''.join(self.algorithm.decrypt(ciphertext[i:i+16]) for i in range(0, len(ciphertext), 16))
            return self.unpad(plaintext).decode('utf-8')

        elif self.mode == 'CBC':
            plaintext = b''
            prev = list(self.iv)
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16]
                decrypted = list(self.algorithm.decrypt(block))
                xored = AES.xor_bytes(decrypted, prev)
                plaintext += bytes(xored)
                prev = list(block)
            return self.unpad(plaintext).decode('utf-8')

        elif self.mode == 'CFB':
            plaintext = b''
            prev = list(self.iv)
            for i in range(0, len(ciphertext), 16):
                keystream = self.algorithm.encrypt(bytes(prev))
                block = list(ciphertext[i:i+16])
                decrypted = AES.xor_bytes(block, list(keystream))
                plaintext += bytes(decrypted)
                prev = block
            return self.unpad(plaintext).decode('utf-8')

        elif self.mode == 'OFB':
            plaintext = b''
            prev = list(self.iv)
            for i in range(0, len(ciphertext), 16):
                prev = list(self.algorithm.encrypt(bytes(prev)))
                block = list(ciphertext[i:i+16])
                decrypted = AES.xor_bytes(block, prev)
                plaintext += bytes(decrypted)
            return self.unpad(plaintext).decode('utf-8')

        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
