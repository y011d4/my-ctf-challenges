# xiyi

Let `enc_x` to be $c$, `enc_alpha` to be $a$ and a random number used in calculating `C.encrypt(r)` to be $s$.
The following is the calculation of $xy$ secretly:

$$
a = c^y g^r h^s = c^y g^{r + ns} \mod n
$$

Here, we can control $c, n$ and accordingly $g, h$. If we can recover $y$ from $a$, we can solve this challenge.

## Generate helpful $p, q$

In order to solve the DLP, we have to generate $p, q$ such that $p - 1, q - 1$ are smooth numbers.

In addition to that, as explaind in the following, we want to recover $r + ns \mod q - 1$ from $r + ns \mod p - 1$.
To do this, the first idea is to generate $p, q$ such that $p - 1 = k(q - 1)$.
But this doesn't work because $p, q$ should have the same bit length.

So alternatively we generate $p, q$ such that $p - 1 = k_p M, q - 1 = k_q M$ where $k_p, k_q$ are small numbers (like around $2^{10}$) and $M$ is a smooth number.
See the following for details.

## Recover $r + ns \mod p - 1$

Specifying $c = 1 + k_cp$, the equation becomes:

$$
a = g^{r + ns} \mod p
$$

Since we specify $p$ as we can solve the DLP, we can recover $r + ns \mod p - 1$ by Pohlig-Hellman algorithm.

## Recover $r + ns \mod q - 1$

Since $p - 1 = k_p M$, we can recover $r + ns \mod M$ from $r + ns \mod p - 1$ easily.
Assuming that $r + ns = i \mod k_q$ for an integer $i$, we can recover $r + ns \mod q - 1$ by CRT.
The number of these candidates is $k_q$, so we can bruteforce it if $k_q$ is small.

## Recover $y$

The equation becomes:

$$
a g^{-r-ns} = c^y \mod q
$$

Now that the LHS is known, we can recover $y$ by solving the DLP.
