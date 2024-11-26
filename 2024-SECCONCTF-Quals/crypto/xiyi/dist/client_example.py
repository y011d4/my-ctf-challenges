import json
from secrets import randbelow

from pwn import remote

from lib import Cryptosystem, Privkey, Pt
from params import L, M, N

if __name__ == "__main__":
    io = remote("localhost", 13333)

    # initialize
    xs = [Pt(randbelow(M)) for _ in range(L)]
    print(f"{xs = }")
    C = Cryptosystem.from_privkey(Privkey.generate(N))
    assert C.privkey is not None
    n = C.pubkey.n
    p = C.privkey.p
    enc_xs = [C.encrypt(x) for x in xs]

    # 1: (client) --- n, enc_xs ---> (server)
    io.sendlineafter(b"> ", json.dumps({"n": n, "enc_xs": enc_xs}).encode())

    # 3: (server) --- enc_alphas, beta_sum_mod_n ---> (client)
    params = json.loads(io.recvline().strip().decode())
    enc_alphas, beta_sum_mod_n = params["enc_alphas"], params["beta_sum_mod_n"]
    alphas = [C.decrypt(enc_alpha) for enc_alpha in enc_alphas]
    alpha_sum = sum(alphas) % p
    inner_product = (alpha_sum + beta_sum_mod_n) % p
    print(f"{inner_product = }")

    # If, by any chance, you can guess ys, send it for the flag!
    ys = [0] * L
    io.sendlineafter(b"> ", json.dumps({"ys": ys, "p": C.privkey.p, "q": C.privkey.q}).encode())
    print(io.recvline().strip().decode())  # Congratz! or Wrong...
    print(io.recvline().strip().decode())  # flag or ys
