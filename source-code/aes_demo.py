# -*- coding: utf-8 -*-
"""
DEMO CAI DAT THUAT TOAN AES (Advanced Encryption Standard)
Su dung thu vien pycryptodome (cai dat: pip install pycryptodome)

Che do su dung: CBC (Cipher Block Chaining)
- Khoa AES: 256 bit (32 byte) - co the doi sang 128/192 bit
- IV (Initialization Vector): sinh ngau nhien 16 byte cho moi lan ma hoa
- Padding: PKCS7 (bat buoc vi AES la block cipher, khoi 16 byte)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time


def aes_encrypt(plaintext: str, key: bytes) -> str:
    """
    Ma hoa chuoi plaintext bang AES-256-CBC.
    Tra ve chuoi base64 gom: IV (16 byte) + ciphertext, de tien luu tru/truyen di.
    """
    iv = get_random_bytes(16)                     # IV ngau nhien, moi lan ma hoa khac nhau
    cipher = AES.new(key, AES.MODE_CBC, iv)        # khoi tao AES o che do CBC
    padded_data = pad(plaintext.encode("utf-8"), AES.block_size)  # dem du 16 byte
    ciphertext = cipher.encrypt(padded_data)       # thuc hien ma hoa (SubBytes/ShiftRows/
                                                    # MixColumns/AddRoundKey qua tung round)
    result = iv + ciphertext                       # ghep IV vao truoc ciphertext
    return base64.b64encode(result).decode("utf-8")


def aes_decrypt(enc_b64: str, key: bytes) -> str:
    """
    Giai ma nguoc lai: tach IV va ciphertext, giai ma, bo padding.
    """
    raw = base64.b64decode(enc_b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plain = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plain, AES.block_size)
    return plaintext.decode("utf-8")


if __name__ == "__main__":
    # Sinh khoa AES-256 ngau nhien (trong thuc te khoa nay can duoc trao doi/luu tru an toan)
    key = get_random_bytes(32)  # 32 byte = 256 bit
    print("Khoa AES (hex):", key.hex())

    message = "Day la du lieu bi mat can ma hoa bang AES - Bai tap An toan bao mat thong tin"
    print("\nBan ro (plaintext):", message)

    t0 = time.perf_counter()
    encrypted = aes_encrypt(message, key)
    t1 = time.perf_counter()
    print("\nBan ma (base64):", encrypted)
    print(f"Thoi gian ma hoa: {(t1 - t0) * 1000:.4f} ms")

    t2 = time.perf_counter()
    decrypted = aes_decrypt(encrypted, key)
    t3 = time.perf_counter()
    print("\nGiai ma:", decrypted)
    print(f"Thoi gian giai ma: {(t3 - t2) * 1000:.4f} ms")

    assert decrypted == message, "Loi: du lieu giai ma khong khop!"
    print("\n=> Ma hoa / giai ma AES thanh cong.")
