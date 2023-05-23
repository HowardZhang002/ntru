from NTRU.NTRUencrypt import NTRUencrypt
from NTRU.NTRUdecrypt import NTRUdecrypt
import argparse

prog_description = """

An implementation of the NTRU encryption algorithm in python3.

Based on the original NTRU paper by Hoffstein, Pipher and Silverman [1].

"""

prog_epilog = """

References:
[1] Hoffstein J, Pipher J, Silverman JH. NTRU: A Ring-Based Public Key Cryptosystem. In: International Algorithmic Number Theory Symposium. Springer; 1998. p. 267--288.

"""


def generate_keys(name="key", mode="highest"):
    if mode not in ["moderate", "high", "highest"]:
        raise ValueError("Input string must be 'moderate', 'high', or 'highest'")
    N1 = NTRUdecrypt()
    if mode == "moderate":
        N1.setNpq(N=107, p=3, q=64, df=15, dg=12, d=5)
    elif mode == "high":
        N1.setNpq(N=167, p=3, q=128, df=61, dg=20, d=18)
    elif mode == "highest":
        N1.setNpq(N=503, p=3, q=256, df=216, dg=72, d=55)
    N1.genPubPriv(name)


def encrypt(name: str, string: str):
    E = NTRUencrypt()
    E.readPub(name + ".pub")
    to_encrypt = string
    E.encryptString(to_encrypt)

    return E.Me


def decrypt(name: str, cipher: str):
    D = NTRUdecrypt()
    D.readPriv(name + ".priv")
    to_decrypt = cipher
    D.decryptString(to_decrypt)

    return D.M


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--message',help='enter message')
    parser.add_argument('--filename','-f',help='enter filename to save keys')
    parser.add_argument('--mode','-m',default = "moderate",help='mode [moderate, high, highest]')
    args = parser.parse_args()
    # m = input("Enter message: ")
    m = args.message
    # f = input("Enter filename to save keys: ")
    f = args.filename
    # mod = input("Enter mode [moderate, high, highest]: ")
    mod = args.mode
    generate_keys(f, mode=mod)  # moderate, high, highest
    enc = encrypt(f, m)
    print("Encrypted message:", enc)
    dec = decrypt(f, enc)
    print("Decrypted message:", dec)
    assert m == dec, "Decryption failed"
    print("\nDecryption was successfully done")