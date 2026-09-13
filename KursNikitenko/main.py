import random
import time
import math
import matplotlib.pyplot as plt


def fmt_time(t):
    return round(t * 1000, 4)


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime():
    while True:
        p = random.randint(200, 600)
        if is_prime(p):
            return p


def mod_inverse(a, m):
    return pow(a, -1, m)


def elgamal_keygen():
    p = generate_prime()
    g = random.randint(2, p - 2)
    x = random.randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x


def elgamal_encrypt(m, pub):
    p, g, y = pub
    k = random.randint(2, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt(c, x, p):
    c1, c2 = c
    s = pow(c1, x, p)
    return (c2 * mod_inverse(s, p)) % p


def elgamal_attack(c1, g, p):
    for x in range(1, p):
        if pow(g, x, p) == c1:
            return x
    return None


def rsa_keygen():
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3

    d = mod_inverse(e, phi)

    return (n, e), d


def rsa_encrypt(m, pub):
    n, e = pub
    return pow(m, e, n)


def rsa_attack(n):
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return i, n // i
    return None


def run():
    iterations = 10

    el_enc = []
    el_att = []
    rsa_enc = []
    rsa_att = []

    el_params = None
    rsa_params = None

    el_msg = None
    el_cipher = None

    rsa_msg = None
    rsa_cipher = None

    print("\n========= EXPERIMENT =========\n")

    for _ in range(iterations):

        pub_e, priv_e = elgamal_keygen()
        p, g, y = pub_e
        msg_e = random.randint(10, p - 1)
        c_e = elgamal_encrypt(msg_e, pub_e)

        if el_params is None:
            el_params = (p, g, y)
            el_msg = msg_e
            el_cipher = c_e

        t1 = time.time()
        elgamal_encrypt(msg_e, pub_e)
        t2 = time.time()
        el_enc.append(t2 - t1)

        t1 = time.time()
        elgamal_attack(c_e[0], g, p)
        t2 = time.time()
        el_att.append(t2 - t1)

        pub_r, priv_r = rsa_keygen()
        n, e = pub_r
        msg_r = random.randint(10, n - 1)
        c_r = rsa_encrypt(msg_r, pub_r)

        if rsa_params is None:
            rsa_params = (n, e)
            rsa_msg = msg_r
            rsa_cipher = c_r

        t1 = time.time()
        rsa_encrypt(msg_r, pub_r)
        t2 = time.time()
        rsa_enc.append(t2 - t1)

        t1 = time.time()
        rsa_attack(n)
        t2 = time.time()
        rsa_att.append(t2 - t1)

    el_enc_avg = sum(el_enc) / iterations
    el_att_avg = sum(el_att) / iterations

    rsa_enc_avg = sum(rsa_enc) / iterations
    rsa_att_avg = sum(rsa_att) / iterations

    print("===== ELGAMAL =====")
    print("p, g, y =", el_params)
    print("message =", el_msg)
    print("cipher =", el_cipher)
    print("encrypt time:", fmt_time(el_enc_avg), "ms")
    print("attack time :", fmt_time(el_att_avg), "ms")

    print("\n===== RSA =====")
    print("n, e =", rsa_params)
    print("message =", rsa_msg)
    print("cipher =", rsa_cipher)
    print("encrypt time:", fmt_time(rsa_enc_avg), "ms")
    print("attack time :", fmt_time(rsa_att_avg), "ms")

    labels = ["ElGamal", "RSA"]

    enc_vals = [el_enc_avg * 1000, rsa_enc_avg * 1000]
    att_vals = [el_att_avg * 1000, rsa_att_avg * 1000]

    plt.figure()
    plt.bar(labels, enc_vals)
    plt.title("Encryption Time Comparison (ms)")
    plt.ylabel("Milliseconds")
    plt.show()

    plt.figure()
    plt.bar(labels, att_vals)
    plt.title("Attack Time Comparison (ms)")
    plt.ylabel("Milliseconds")
    plt.show()


if __name__ == "__main__":
    run()

