# Entropoid Increase

## Discrete Entropoid Logarithmic Problem (DELP) to simple DLP

You can refer to https://eprint.iacr.org/2021/583.pdf or https://eprint.iacr.org/2021/1472.pdf.
The notation here follows these original articles.

Using the map $\sigma$, we can transform the non-associative and non-commutative structure of $(\mathbb{E}, *)$ into the abelian group structure of $(\mathbb{E}, \cdot)$:

$$
x * y = \sigma(x) \cdot y
$$

where

$$
\begin{align*}
\sigma((x_1, x_2)) &\equiv \left(
\frac{a_8}{b_7}x_2 + \frac{a_8^2 b_2 - a_3 b_7^2}{a_8 b_7^2}, \frac{b_7}{a_8}x_1 + \frac{a_3 b_7^2 - a_8^2 b_2}{a_8^2 b_7}
\right) \\
(x_1, x_2) \cdot (y_1, y_2) &\equiv \left(
b_7 x_1 y_1 + \frac{a_3 b_7}{a_8}x_1 + \frac{a_3 b_7}{a_8}y_1 + \frac{a_3^2 b_7 - a_3 a_8}{a_8^2},
a_8 x_2 y_2 + \frac{a_8 b_2}{b_7}x_2 + \frac{a_8 b_2}{b_7}y_2 + \frac{a_8 b_2^2 - b_2 b_7}{b_7^2}
\right)
\end{align*}
$$

To make the operation $(x_1, x_2) \cdot (y_1, y_2)$ above into a simple structure, where the operation can be considered for each component of them, just consider the following isomorphic map $\iota$:

$$
\iota: \mathbb{E} \to (\mathbb{F}_p)^2, (x_1, x_2) \mapsto \left(
b_7 x_1 + \frac{a_3 b_7}{a_8}, a_8 x_2 + \frac{a_8 b_2}{b_7}
\right)
$$

Since $\sigma(\sigma(x)) = x$, we can write $x^{\boldsymbol{A}}$ as the form $x^{\boldsymbol{A}} = x^i \cdot \sigma(x)^j$ using $i, j$. If we find such $i, j$, we can recover the shared key by DH.

Let $(\alpha_1, \alpha_2) = \iota(g)$, $(\beta_1, \beta_2) = \iota(\sigma(g))$, $(\gamma_1, \gamma_2) = \iota(g^{\boldsymbol{A}})$.
In order to find $i, j$ such that $g^{\boldsymbol{A}} = g^i \cdot \sigma(g)^j$, we have to solve $\alpha_1^i \beta_1^j = \gamma_1$ and $\alpha_2^i \beta_2^j = \gamma_2$. Using a multiplicative generator $\kappa$ in $\mathbb{F}_p$, let $r_k = \log_{\kappa}(\alpha_k)$, $s_k = \log{\kappa}(\beta_k)$, $t_k = \log{\kappa}(\gamma_k)$. We can obtain the following:

$$
(i j)
\left(
\begin{array}{cc}
r_1 & r_2 \\
s_1 & s_2
\end{array}
\right)
= (t_1 t_2) \mod p - 1
$$

So if $\log_{\kappa}(\cdots)$ can be computed, DELP can be solved.

In this challenge, there are two parameters. The first parameter's $p$ for debug is 64 bits, which is solvable. On the other hand, the second one's $p$ is 2048 bits, which is difficult to solve but should be solved.

Note that even if we could solve DELP, we cannot recover the private key (power index), because a private key corresponding to a public key is not unique.

## Recover the state of python's random

Since it seems difficult to solve 2048 bits Entropoid, we should find another approach.

In the script `problem.sage`, `randrange` is used in `Entropoid.random_power_index`. This uses python's `random`. So if we know many outputs of `randrange`, we can recover the state of random and private key directly.

As mentioned above, we cannot recover full of private keys. But is there any leaked parts of it?

Looking into carefully about the exponential calculation in entropoid, $i + j$ is not changed by the bracketing patterns and $i + j$ should be the number of $g$ (`a_num`), which is the first argument of the power index. 
Using this fact, we can recover the output of the first `randrange` in `random_power_index`.

We can collect them as many as we can recover the state and predict the private key used for the last shared key.
