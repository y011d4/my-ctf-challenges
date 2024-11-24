import json

from pwn import remote, context
from tqdm import tqdm

context.log_level = "DEBUG"


L = 32  # The length of the vector
M = 2**256  # The upper bound of the elements in the vector
N = 518  # The bit length of primes


def generate_primes():
    """
    for example:
        p = 742860286757290487929435912213135396522985118496895051281469517993499753333438264768808315370284937038698645358823562793054516936174962902445900384965709069
        q = 775992553068061659926288687640481810921897600307789431502943510580064296322488328220938263708396237047466894799710059725139108067131123219691140073497043511
    """
    # while True:
    #     k = 2
    #     while True:
    #         k *= random_prime(2**16)
    #         if k.bit_length() >= N - 8:
    #             break
    #     ps = []
    #     for i in range(1, 2**10):
    #         p = k * i + 1
    #         if is_prime(p) and p.bit_length() == N:
    #             ps.append(p)
    #         if len(ps) == 2:
    #             print("found")
    #             break
    #     if len(ps) == 2:
    #         p, q = ps
    #         n = p**2 * q
    #         g = n // 2
    #         if Zmod(p)(g).multiplicative_order() == p - 1 and Zmod(q)(g).multiplicative_order() == q - 1:
    #             break
    # p, q = ps
    p = 742860286757290487929435912213135396522985118496895051281469517993499753333438264768808315370284937038698645358823562793054516936174962902445900384965709069
    q = 775992553068061659926288687640481810921897600307789431502943510580064296322488328220938263708396237047466894799710059725139108067131123219691140073497043511
    return p, q


def calc_enc_x(p, q):
    enc_x = 1 + p
    while True:
        if Zmod(q)(enc_x).multiplicative_order() == q - 1:
            return enc_x
        enc_x += p



def solve(p, q, g, enc_x, enc_alpha):
    enc_alpha_log_g = discrete_log(GF(p)(enc_alpha), GF(p)(g))
    k = gcd(p - 1, q - 1)

    enc_alpha_log_enc_x = discrete_log(GF(q)(enc_alpha), GF(q)(enc_x))
    g_log_enc_x = discrete_log(GF(q)(g), GF(q)(enc_x))
    for i in range((q - 1) // k):
        tmp = crt([i, enc_alpha_log_g % k], [(q - 1) // k, k])
        res = (enc_alpha_log_enc_x - g_log_enc_x * tmp) % (q - 1)
        if res.bit_length() <= 256:
            print(res)
            return res


if __name__ == "__main__":
    io = remote("localhost", 13333)

    p, q = generate_primes()
    n = p**2 * q
    g = n // 2

    enc_x = calc_enc_x(p, q)
    enc_xs = [int(enc_x)] * L
    io.sendlineafter(b"> ", json.dumps({"n": int(n), "enc_xs": enc_xs}).encode())
    ret = io.recvline().strip().decode()
    params = json.loads(ret)
    enc_alphas, beta_sum_mod_n = params["enc_alphas"], params["beta_sum_mod_n"]
    ys = []
    alpha_sum = 0
    for enc_alpha in tqdm(enc_alphas):
        ys.append(solve(p, q, g, enc_x, enc_alpha))

    io.sendlineafter(b"> ", json.dumps({"ys": [int(y) for y in ys], "p": int(p), "q": int(q)}).encode())
    print(io.recvline().strip().decode())
    print(io.recvline().strip().decode())
