# broken oracle

## Solution

This oracle calculates `encrypt(decrypt(input))`.
So if the calculation is entirely correct, the returned value should be the same as the input.
But with some experimentation, you can find that the oracle sometimes returns different values or even "Something wrong...".
You can check where this miscalculation happens.

There is a bug, as far as I know, in `solve_quad` function.
This function implicitly requires $x^2 + rx + c = 0 \mod p$ have a solution.
This equation has no solution when
$$
\left( \frac{r^2/4-c}{p}\right) = -1
$$
because $x^2 + rx + c = 0 \iff (x + r/2)^2 = r^2/4 - c$.
When this is not satisfied, `solve_quad` returns an undefined value.

### Recover $p, q$

Here, in `decrypt`, consider the case where $r^2/4-c$ is a quadratic residue modulo $p$, but not modulo $q$.
Let the encryption of the decrypted result of $r$ to be $r'$.
In this case, $r = r'$ in $\mathrm{GF}(p)$, while $r \ne r'$ in $\mathrm{GF}(q)$.
This means that $r' - r$ is a multiple of $p$, while is not a multiple of $q$.
Therefore when we collect some $r_i' = \mathrm{Enc}(\mathrm{Dec}(r_i))$, we can recover $p$ by $\gcd(r_i' - r_i, r'_j - r_j)$ on some $(i, j)$.
Of course this holds true for $q$.

### Recover $c$

In the cryptosystem, $c$ is a plublic key.
But in this challenge $c$ is not disclosed (sorry, it's because this is CTF).

Let $a_1, a_2 = \mathrm{solve\_quad}(r, c, p)$ and $b_1, b_2 = \mathrm{solve\_quad}(r, c, q)$, where $r$ satisfies $\left( \frac{r^2/4-c}{p}\right) = \left( \frac{r^2/4-c}{q}\right) = -1$.
We can get $r_1, r_2$ such that $r_1 = \mathrm{Enc}(m_1), r_2 = \mathrm{Enc}(m_2)$ where $m_1 = a_1 \mod p, m_1 = b_1 \mod q, m_2 = a_2 \mod p, m_2 = b_2 \mod q$ by changing $s, t$ with the same $r$.
Since $m_2 = r - m_1 \mod n$, the following equations hold:

$$
\begin{align*}
m_1^2 - r_1 m_1 + c &= 0 & \mod n \\
(r - m_1)^2 - r_1 (r - m_1) + c &= 0 & \mod n
\end{align*}
$$

We can solve this by hand:

$$
\begin{align*}
m_1 = \frac{r_2 r - r^2}{r_1 - 2r + r_2} & \mod n \\
c = r_1 m_1 - m_1^2 & \mod n
\end{align*}
$$

So we can recover $c, m_1$ from $r, r_1, r_2$.

Now that we recover public keys $n, c$ and private keys $p, q$, we can decrypt the flag.
