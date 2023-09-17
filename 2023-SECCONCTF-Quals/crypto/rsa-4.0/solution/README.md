# RSA 4.0

Let $M$ be the message to be encrypted:

$$
\begin{align*}
M &= m + (3 m + p + 337 q) i + (3 m + 13 p + 37 q) j + (7 m + 133 p + 7 q) k \\
&\equiv a + bi + cj + dk
\end{align*}
$$

## Factor $n$

Let's calculate the power of $M$. We'll denote by $a_i, b_i, c_i, d_i$:

$$
\begin{align*}
M^i &= a_i + b_i i + c_i j + d_i k \\
a_1 &= a \\
b_1 &= b \\
c_1 &= c \\
d_1 &= d
\end{align*}
$$

Then,

$$
M^2 = a^2 - b^2 - c^2 - d^2 + 2abi + 2acj + 2adk
$$

$$
M^3 = a^3 - 3ab^2 - 3ac^2 - 3ad^2 + b(3a^2 - b^2 - c^2 - d^2)i + c(3a^2 - b^2 - c^2 - d^2)j + d(3a^2 - b^2 - c^2 - d^2)k
$$

...

It implies that we can describe $ b_n, c_n, d_n$ by $L_n$ such that $b_n = bL_n, c_n = cL_n, d_n = dL_n$ ($n \in \mathbb{N}$). It can be proved by mathematical induction as follows:

When $n = 0$, it clearly satisfies the statement by definition.

Next, assume that it satisfies the statement when $n = l$,

$$
\begin{align*}
M^{l+1} &= M^l M \\
&= (a_l + b_l i + c_l j + d_l k)(a + b i + c j + d k) \\
&= (a_l + b L_l i + c L_l j + d L_l k)(a + b i + c j + d k) \\
&= (a_l a - (b^2 + c^2 + d^2) L_l) + b (a L_l + a_l) i + c (a L_l + a_l) j + d (a L_l + a_l) k
\end{align*}
$$

Therefore, it also satisfies the statement when $n = l + 1$ ($L_{l+1} = a L_l + a_l$). This completes the proof by mathematical induction.

Using this fact, we can compose a multiple of $p$ by linear superposition of $b_{65537} = (3m+p+337q)L_{65537}, c_{65537} = (3m+13p+37q)L_{65537}, d_{65537} = (7m + 133p + 7q)L_{65537}$, where $b_{65537}, c_{65537}, d_{65537}$ are given numbers.
This can be done by solving the following linear equation:

$$
\left(
\begin{array}{c}
0 \\
1 \\
0
\end{array}
\right) = x
\left(
\begin{array}{ccc}
3 & 1 & 337 \\
3 & 13 & 37 \\
7 & 133 & 7
\end{array}
\right)
$$

where $x$ is a 3-dim row vector.
The solution of this equation is a vector of fractions. But we can transform it into a vector of integers by multiplying the lcm of denominators.
Using a multiple of $p$, we can recover $p$ by calculating the gcd with $n$ and it.

## Recover $m$

There are two ways to recover it:

- Find the multiplicative order
- Use the linear relation shown above

### Find the multiplicative order

In the above section, we found that $a_{l+1} = a a_l - (b^2 + c^2 + d^2) L_l$, $L_{l+1} = a_l + a L_l$. This can be written in a matrix form:

$$
\left(
\begin{array}{c}
a_{l+1} \\
L_{l+1}
\end{array}
\right) =
\left(
\begin{array}{cc}
a & -(b^2 + c^2 + d^2) \\
1 & a
\end{array}
\right)
\left(
\begin{array}{c}
a_l \\
L_l
\end{array}
\right)
\equiv
A
\left(
\begin{array}{c}
a_l \\
L_l
\end{array}
\right)
$$

$A$ can be diagonalized as follows:

$$
\begin{align*}
D &\equiv
\left(
\begin{array}{cc}
a + \sqrt{-(b^2 + c^2 + d^2)} & 0 \\
0 & a - \sqrt{-(b^2 + c^2 + d^2)}
\end{array}
\right) \\
P &\equiv
\left(
\begin{array}{cc}
\sqrt{-(b^2 + c^2 + d^2)} & -\sqrt{-(b^2 + c^2 + d^2)} \\
1 & 1
\end{array}
\right) \\
A &= P D P^{-1}
\end{align*}
$$

First consider these matrices in the field $\mathbb{F}_p$.
The multiplicative order of this matrix is a divisor of $p^2 - 1$ (note that $-(b^2 + c^2 + d^2) < 0$).
This shows that the multiplicative order of $M$ in $\mathbb{F}_p$ is also a divisor of $p^2 - 1$.

This discussion can be applied to the case $\mathbb{F}_q$.
Therefore the multiplicative order of $M$ in $\mathbb{Z}_n$ is a divisor of $(p^2 - 1)(q^2 - 1)$.

In order to decrypt this RSA-like system, we would like to know the order.
We will show that the order is a divisor of $(p^2 - 1)(q^2 - 1)$, which is almost the same way as a proof of Fermat's little theorem.

Now that we know a multiple of the multiplicative order, we can decrypt `enc` in the same way as RSA:

$$
d = e^{-1} \mod (p^2 - 1)(q^2 - 1) \\
M = (M^e)^d \mod n
$$

### Use the linear relation shown above

Actually, we don't need to find the multiplicative order in this challenge.

We have two equations derived in "Factor n" section (actually we have three equations but we don't need one):

$$
\begin{align*}
b_{65537} &= (3m + p + 337q) L_{65537} \\
c_{65537} &= (3m + 13p + 37q) L_{65537} \\
\end{align*}
$$

We can remove $L_{65537}$ from those equations and obtain $b_{65537} (3m + 13p + 37q) = c_{65537} (3m + p + 337q)$.
Since we know all variables except $m$, we can recover $m$ from this simple equation.
