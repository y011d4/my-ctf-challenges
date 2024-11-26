"""Calculate the inner product of client's xs and server's ys without leaking ys by homomorphic encryption.

- Each of client's xs, x, is encrypted to enc_x = encrypt(x) and is sent to the server.
- The server calculates enc_alpha = enc_x^y * (-beta), where beta is randomly generated.
- The client can get alpha = decrypt(enc_alpha) such that x * y = alpha + beta because of the homomorphic encryption.
- Finally, the server sends the sum of beta and the client gets the inner product by sum(alpha) + sum(beta).
"""

import json
import os
import signal
from secrets import randbelow

from Crypto.Util.number import isPrime

from lib import Cryptosystem, Pt, Pubkey
from params import L, M, N

flag = os.getenv("FLAG", "SECCON{this_is_not_a_flag}")


def input_json(prompt: str) -> dict:
    params = json.loads(input(prompt))
    assert isinstance(params, dict)
    return params


if __name__ == "__main__":
    signal.alarm(300)

    # initialize
    ys = [randbelow(M) for _ in range(L)]

    # 2: (client) --- n, enc_xs ---> (server) --- enc_alphas, beta_sum_mod_n ---> (client)
    params = input_json('{"n": ..., "enc_xs": [...]} > ')
    n, enc_xs = params["n"], params["enc_xs"]
    assert isinstance(n, int) and n > 0
    assert isinstance(enc_xs, list) and len(enc_xs) == L and all([isinstance(x, int) for x in enc_xs])
    C = Cryptosystem.from_pubkey(Pubkey(n))
    enc_alphas = []
    betas = []
    for enc_x, y in zip(enc_xs, ys, strict=True):
        r = Pt(randbelow(n))
        enc_alpha = C.add(C.mul(enc_x, Pt(y)), C.encrypt(r))
        beta = -r % n
        enc_alphas.append(enc_alpha)
        betas.append(beta)
    beta_sum_mod_n = sum(betas) % n
    print(json.dumps({"enc_alphas": enc_alphas, "beta_sum_mod_n": beta_sum_mod_n}))

    # BTW, can you guess ys?
    params = json.loads(input('{"ys": [...], "p": ..., "q": ...} > '))
    guessed_ys, p, q = params["ys"], params["p"], params["q"]
    assert (
        n == p**2 * q and p.bit_length() == q.bit_length() == N and p != q and isPrime(p) and isPrime(q)
    ), "Don't cheat me!"
    if guessed_ys == ys:
        print("Congratz!")
        print(flag)
    else:
        print("Wrong...")
        print(f"{ys = }")
