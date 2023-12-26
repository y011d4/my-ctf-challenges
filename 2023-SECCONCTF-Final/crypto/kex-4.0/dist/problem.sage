import os
from hashlib import sha256
from secrets import randbelow

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes


FLAG = os.getenvb(b"FLAG", b"FAKEFLAG{THIS_IS_FAKE}")

p = 0xC20C8EDB31BFFA707DC377C2A22BE4492D1F8399FFFD388051EC5E4B68B4598B
order = p**2 - 1
Q = QuaternionAlgebra(Zmod(p), -1, -1)
i, j, k = Q.gens()
pub_A = (
    71415146914196662946266805639224515745292845736145778437699059682221311130458
    + 62701913347890051538907814870965077916111721435130899071333272292377551546304 * i
    + 60374783698776725786512193196748274323404201992828981498782975421278885827246 * j
    + 60410367194208847852312272987063897634106232443697621355781061985831882747944 * k
)
pub_B = (
    57454549555647442495706111545554537469908616677114191664810647665039190180615
    + 8463288093684346104394651092611097313600237307653573145032139257020916133199 * i
    + 38959331790836590587805534615513493167925052251948090437650728000899924590900 * j
    + 62208987621778633113508589266272290155044608391260407785963749700479202930623 * k
)


def hash_Q(x):
    return sha256(
        long_to_bytes(int(x[0]))
        + long_to_bytes(int(x[1]))
        + long_to_bytes(int(x[2]))
        + long_to_bytes(int(x[3]))
    ).digest()


if __name__ == "__main__":
    # Alice sends share_A to Bob
    priv_A = randbelow(order)
    A = pub_A**priv_A
    share_A = A**-1 * pub_B * A
    print(f"{share_A = }")
    # Bob sends share_B to Alice
    priv_B = randbelow(order)
    B = pub_B**priv_B
    share_B = B**-1 * pub_A * B
    print(f"{share_B = }")
    # Alice computes the shared key
    Ka = A**-1 * share_B**priv_A
    # Bob computes the shared key
    Kb = share_A**-priv_B * B
    assert Ka == Kb

    # Encrypt FLAG with the shared key
    key = hash_Q(Ka)
    cipher = AES.new(key, mode=AES.MODE_CTR)
    nonce = cipher.nonce.hex()
    enc = cipher.encrypt(FLAG).hex()
    print(f"{nonce = }")
    print(f"{enc = }")
