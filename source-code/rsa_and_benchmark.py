# -*- coding: utf-8 -*-
"""
DEMO RSA: sinh cap khoa, ma hoa/giai ma, ky so (chu ky dien tu)
+ BENCHMARK so sanh thoi gian RSA vs AES
Thu vien: pycryptodome
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import time


# ================== 1. SINH CAP KHOA RSA ==================
def generate_rsa_keypair(bits: int = 2048):
    """
    Sinh cap khoa RSA:
    - Chon 2 so nguyen to lon p, q (thu vien tu lam ben trong)
    - n = p*q ; phi(n) = (p-1)(q-1)
    - Chon e (thuong = 65537), tinh d = e^-1 mod phi(n)
    - public key = (e, n) ; private key = (d, n)
    """
    key = RSA.generate(bits)
    return key, key.publickey()


# ================== 2. MA HOA / GIAI MA BANG RSA (xac thuc NGUOI NHAN) ==================
def rsa_encrypt(plaintext: bytes, public_key) -> bytes:
    """Nguoi gui dung PUBLIC KEY cua nguoi nhan de ma hoa -> chi nguoi nhan giai ma duoc."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    """Nguoi nhan dung PRIVATE KEY cua chinh minh de giai ma."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


# ================== 3. KY SO (xac thuc NGUOI GUI) ==================
def sign_message(message: bytes, private_key) -> bytes:
    """Nguoi gui dung PRIVATE KEY cua chinh minh de 'ma hoa' hash -> tao chu ky."""
    h = SHA256.new(message)
    return pkcs1_15.new(private_key).sign(h)


def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    """Ai cung co the dung PUBLIC KEY cua nguoi gui de xac minh chu ky."""
    h = SHA256.new(message)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ================== 4. MO HINH KET HOP RSA + AES (Hybrid Encryption) ==================
def hybrid_encrypt(plaintext: bytes, receiver_public_key):
    """
    Buoc 1: sinh khoa AES ngau nhien (session key) -> ma hoa DU LIEU (nhanh)
    Buoc 2: dung RSA public key cua nguoi nhan de ma hoa KHOA AES (du lieu nho)
    """
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=iv)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    return {
        "enc_aes_key": enc_aes_key,   # khoa AES da duoc RSA ma hoa
        "iv": iv,
        "tag": tag,
        "ciphertext": ciphertext,
    }


def hybrid_decrypt(payload: dict, receiver_private_key) -> bytes:
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
    aes_key = cipher_rsa.decrypt(payload["enc_aes_key"])  # giai ma ra khoa AES

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=payload["iv"])
    plaintext = cipher_aes.decrypt_and_verify(payload["ciphertext"], payload["tag"])
    return plaintext


# ================== 5. BENCHMARK SO SANH RSA vs AES ==================
def benchmark():
    message = b"Du lieu demo de so sanh toc do ma hoa giua RSA va AES." * 2  # ~100+ byte

    # --- AES ---
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    t0 = time.perf_counter()
    ct, tag = cipher_aes.encrypt_and_digest(message)
    t1 = time.perf_counter()
    aes_enc_time = (t1 - t0) * 1000

    cipher_aes2 = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    t2 = time.perf_counter()
    _ = cipher_aes2.decrypt_and_verify(ct, tag)
    t3 = time.perf_counter()
    aes_dec_time = (t3 - t2) * 1000

    # --- RSA (chi ma hoa duoc du lieu nho hon kich thuoc khoa) ---
    priv, pub = generate_rsa_keypair(2048)
    small_msg = message[:100]  # RSA-2048 + OAEP chi ma hoa toi da ~190 byte
    cipher_rsa = PKCS1_OAEP.new(pub)
    t4 = time.perf_counter()
    rsa_ct = cipher_rsa.encrypt(small_msg)
    t5 = time.perf_counter()
    rsa_enc_time = (t5 - t4) * 1000

    cipher_rsa2 = PKCS1_OAEP.new(priv)
    t6 = time.perf_counter()
    _ = cipher_rsa2.decrypt(rsa_ct)
    t7 = time.perf_counter()
    rsa_dec_time = (t7 - t6) * 1000

    print("=== KET QUA BENCHMARK (cang nho cang nhanh) ===")
    print(f"AES  - ma hoa: {aes_enc_time:.4f} ms | giai ma: {aes_dec_time:.4f} ms")
    print(f"RSA  - ma hoa: {rsa_enc_time:.4f} ms | giai ma: {rsa_dec_time:.4f} ms")
    print(f"\n=> RSA giai ma cham hon AES khoang {rsa_dec_time / aes_dec_time:.1f} lan "
          f"(voi cung du lieu nho).")
    print("=> Do do RSA chi nen dung de trao doi khoa / ky so, "
          "con du lieu lon nen dung AES (mo hinh Hybrid).")


if __name__ == "__main__":
    print(">>> 1. SINH CAP KHOA RSA")
    private_key, public_key = generate_rsa_keypair(2048)
    print("Public key (n, e) da san sang. Private key (d, n) duoc giu bi mat.\n")

    print(">>> 2. MA HOA/GIAI MA RSA (xac thuc NGUOI NHAN)")
    msg = b"Chao ban, day la thong diep bi mat!"
    enc = rsa_encrypt(msg, public_key)
    dec = rsa_decrypt(enc, private_key)
    print("Ban ro:", msg)
    print("Giai ma:", dec, "\n")

    print(">>> 3. KY SO (xac thuc NGUOI GUI)")
    signature = sign_message(msg, private_key)
    is_valid = verify_signature(msg, signature, public_key)
    print("Chu ky hop le:", is_valid, "\n")

    print(">>> 4. MO HINH KET HOP RSA + AES (Hybrid)")
    payload = hybrid_encrypt(b"Du lieu lon can ma hoa nhanh bang AES, khoa duoc bao ve boi RSA.",
                              public_key)
    result = hybrid_decrypt(payload, private_key)
    print("Giai ma hybrid:", result, "\n")

    print(">>> 5. BENCHMARK\n")
    benchmark()
