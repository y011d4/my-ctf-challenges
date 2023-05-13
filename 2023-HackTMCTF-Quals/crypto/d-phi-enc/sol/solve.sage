from Crypto.Util.number import long_to_bytes

with open("./output.txt") as fp:
    exec(fp.read())

e = 3

for k in range(3):
    for m in range(100):
        PR = PolynomialRing(ZZ, names=["p_q"])
        p_q = PR.gens()[0]
        f = (k^3 * enc_phi + 3 * k^2 * (1 - p_q)^2 + 3 * k * (1 - p_q) + 1) - enc_d * e^3 - m * n
        roots = f.roots()
        if len(roots) > 0:
            print(k, m, roots)
            PR = PolynomialRing(ZZ, names=["z"])
            z = PR.gens()[0]
            g = z ** 2 - int(roots[0][0]) * z + n
            p, q = g.roots(multiplicities=False)
            phi = (p - 1) * (q - 1)
            d = int(pow(e, -1, phi))
            print(long_to_bytes(int(pow(enc_flag, d, n))))
