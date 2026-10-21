# Ryan Tagen
# Reference: https://www.teach.cs.toronto.edu/~csc110y/fall/notes/08-cryptography/05-rsa-cryptosystem-implementation.html
# https://www.askpython.com/python/examples/rsa-algorithm-in-python 

import random
import math

# Variables
key_size = 512
input_text = input("Enter text: ")

# Miller-Rabin primality test
# http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
def is_prime(n, k = 40):
    # k = 40 is optimal number of rounds

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate a random prime with the specified number of bits
def generate_prime(bits: int) -> int:
    while True:
        candidate = random.randint(2 ** (bits - 1), 2 ** bits - 1)

        if is_prime(candidate):
            return candidate

# Find the modular inverse using the extended euclidean algorithm
def modular_inverse(a: int, m: int) -> int:
    old_r, r = a, m
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    if old_r != 1:
        raise ValueError("No modular inverse")

    return old_s % m

# Generate RSA keys from two primes
def rsa_generate_key(p: int, q: int):
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e coprime to phi_n
    e = random.randint(2, phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # private exponent
    d = modular_inverse(e, phi_n)

    private_key = (p, q, d)
    public_key = (n, e)

    return private_key, public_key


# Encrypt a single number
# c = m^e mod n
def rsa_encrypt(public_key: tuple, plaintext: int) -> int:
    n, e = public_key

    if not 0 <= plaintext < n:
        raise ValueError("Plaintext must be between 0 and n - 1.")

    return pow(plaintext, e, n)


# Decrypt a single number
def rsa_decrypt(private_key: tuple, ciphertext: int) -> int:
    p, q, d = private_key
    n = p * q

    return pow(ciphertext, d, n)


# Encrypt text character by character
# Returns a list of encrypted integers.
def rsa_encrypt_text(public_key: tuple, plaintext: str) -> list:
    encrypted = []

    for letter in plaintext:
        encrypted.append(rsa_encrypt(public_key, ord(letter)))

    return encrypted


# Decrypt a list of encrypted integers back into text
def rsa_decrypt_text(private_key: tuple, ciphertext: list) -> str:
    decrypted = ""

    for number in ciphertext:
        decrypted += chr(rsa_decrypt(private_key, number))

    return decrypted


# Generate two distinct primes
prime_bits = key_size // 2
while True:
    p = generate_prime(prime_bits)
    q = generate_prime(key_size - prime_bits)

    if p != q:
        break

# Generate the key pair
private_key, public_key = rsa_generate_key(p, q)

# Encrypt and decrypt the input
ciphertext = rsa_encrypt_text(public_key, input_text)
decrypted_text = rsa_decrypt_text(private_key, ciphertext)

# Display results
print("Key size:", key_size, "bits")
print("Prime p:", p)
print("Prime q:", q)
print("Private key (p, q, d):", private_key)
print("Public key (n, e):", public_key)
print("Original text:", input_text)
print("Encrypted numbers:", ciphertext)
print("Decrypted text:", decrypted_text)
print("Successful:", input_text == decrypted_text)