# seqr

This challenge is simple, break ECDSA with PRNG by legendre symbol.

## Break PRNG by legendre symbol

As mentioned in docstring, Legendre PRF is believed to be secure, as far as I googled.
So if the implementation is correct, it is impossible to break the PRNG.
...But this is CTF. There should be some vulnerabilities.

The first valunerability is:

```python
    p = int(input("Your favorite 256-bit prime (hex) > "), 16)
    if p.bit_length() != 256:
        print("p must be 256-bit")
        exit()
    a = randbelow(p)
    prng = PRNG(a, p)
```

`p` should be a prime, but the server doesn't check it. So we can set `p` to a composite number.

The second is:

```python
            tmp = legendre(self._state, self.p)
```

At first sight, this is not a problem. But gmpy2's `legendre` doesn't also check if `self.p` is a prime :angry:.
`legendre` calculates as if it's `jacobi` symbol.
This always causes the output to be 1 (in terms of PRNG) if `self._state` isn't coprime with `self.p`.
If you specify `p` as a smooth number like $p = 2 \times 3 \times 5 \times \cdots$, most of the PRNG's outputs are 1 regardless of the initial state.

## Break ECDSA

There may some ways to break it.

In my solution, I focus on multiples of 3 and 11.
When $a + 256n = 0 \mod 3, a + 256n + 1 = 0 \mod 11$ for integer $n$, it's also satisfied that $a + 256n + 255 = 0 \mod 3, a + 256n + 254 = 0 \mod 11$.
In this case, $n$-th $k$ is like `11[01]{252}11`.
This also holds true periodically for $(n + 33)$-th, $(n + 66)$-th, and so on, because $\gcd(33, 256) = 1$.
In this way we can get around 100 signatures where $k$ has the form of that.
Although we don't actually know which one of 33 possibilities satisfies the above condition, we can try all of them assuming that they satisfy it.

In order to recover $d$ as the HNP, we need to transform $k$ into the form of `0000[01]{252}`.
Let transformed $k$ to be $k'$ and signatures and message hash accordingly to be $r', s', z'$.
Since $4k' = 2^{256} - 1 - k = 2^{256} - 1 - s^{-1}z - s^{-1}rd$ equals to $4s'^{-1}(z' + r'd)$,

$$
\begin{align*}
4s'^{-1}z' &= 2^{256} - 1 - s^{-1}z \\
4s'^{-1}r' &= -s^{-1}r \\
r' &= (k'G)_x
\end{align*}
$$

From here, we can get $r', s', z'$ by

$$
\begin{align*}
r' &= 4^{-1}(2^{256} - 1)G - R \\
s' &= -4r^{-1}sr' \\
z' &= 4^{-1}s'(2^{256} - 1 - s^{-1}z)
\end{align*}
$$

where $R$ is one of elliptic curve point where $R_x = r$.

There are many researches about solving the HNP with 4-bit leaks, for example, [On Bounded Distance Decoding with Predicate: Breaking the "Lattice Barrier" for the Hidden Number Problem]() and [Return of the Hidden Number Problem](https://tches.iacr.org/index.php/TCHES/article/view/7337).
But in my experiments, we can solve it with 90 signatures by BKZ with block size 25, with a probability of around 25%.
