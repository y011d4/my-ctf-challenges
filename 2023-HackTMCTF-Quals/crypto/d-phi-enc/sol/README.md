# d-phi-enc

## Solution

All we need is analytical calculation. Let $E_d, E_{\phi}$ be the encryption of $d, \phi$ and $ed = k \phi + 1$

$$
\begin{align*}
0 &= (k\phi + 1)^3 - (ed)^3 \\
&= k^3 E_{\phi} + 3k^2 \phi^2 + 3 k \phi + 1 - e^3 E_d \mod n \\
&= k^3E_{\phi} + 3k^2(1 - p - q)^2 + 3k(1 - p - q) + 1 - e^3 E_d \mod n \\
\end{align*}
$$

The second term is less than $n$.
The first term is $k^3 E_{\phi} < 27n$.
The second term is, since $(1 - p - q)^2 = (p + q)^2 - 2(p + q) + 1 \simeq p^2 + 2n + q^2 \simeq 4n$, $3k^2(1-p-q)^2 < 108n$.
The last term is $e^3 E_d < 27n$
Therefore the r.h.s is around $200n$ at most.
(As a matter of fact, we can show $k = 2$ in any case.)

We can then recover $p + q$ by assuming $k$ and the exact value of the r.h.s.
If the assumption is right, the above equation without mod has solution.

From $p + q$ and $pq = n$, we can also recover $p, q$ by simply finding roots of $z^2 - (p + q)z + n = 0$.

```python
for k in range(3):
    for m in range(200):
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
```
