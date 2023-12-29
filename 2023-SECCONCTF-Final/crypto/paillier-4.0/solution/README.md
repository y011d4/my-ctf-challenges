# Paillier 4.0

## Solution

This cryptosystem is almost the same as [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem). The difference from it is calculation is not in integers modulo $n$ but quaternions modulo $n$.

### Simplification

A message $m$ is encrypted to $c$ as follows:

$$
c = g^m k^n
$$

Let $g = 1 + hn$. You can find that $g^m = (1 + hn)^m = 1 + mhn = 1 + m(g - 1) \mod n^2$.
We will denote a quaternion $x$ as $x = x_0 + x_1 i + x_2 j + x_3 k$ where $x_n$ is an integer. Using this notation, the relation between $m$ and $c$ is written as:

$$
\begin{aligned}
c_0 &= (g_0 - 1)mk^n + k^n \\
c_1 &= g_1 mk^n \\
c_2 &= g_2 mk^n \\
c_3 &= g_3 mk^n \\
\end{aligned}
$$

Therefore, if you are given $c, g, n$, you can recover $m$ by calculating $mk^n = c_1 g_1^{-1}, k^n = c_0 - (g_0 - 1)mk^n, m = mk^n (k^n)^{-1}$.

### Recover $n, g$

But this challenge doesn't give $g, n$ (it's not realistic situation though). You have to do something a little more.

$n$ can be easily recovered: since $c_i = nh_i mk^n \mod n^2 (i \ge 1)$, you can recover a multiple of $n$ by $\gcd(c_1, c_2, c_3)$.

Next, consider using a plaintext-ciphertext pair (let them to be $m^{(0)}, c^{(0)}$).
Since Paillier is homomorphic, $c^{(1)} = c^{(0)} (m^{(0)})^{-1} \mod n$ is a encryption of 1. Also, $c^{(1)}$ must be $g (k^{(1)})^n$.
Using the fact that $g_0 = 1 \mod n$, you can recover $g \mod n$ by $g = c^{(1)} (c_0^{(1)})^{-1} \mod n$.

Since $m$ should be less than $n$, $g \mod n$ is sufficient to recover $m$ by the method described in Simplification section.
