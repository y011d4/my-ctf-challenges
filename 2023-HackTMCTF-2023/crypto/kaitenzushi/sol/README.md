# kaitenzushi

## Overview

In this challenge, we are given RSA's $n$ and $c$, without $e$.
In addition to that, the flag is xored by $x_1, y_1, x_2, y_2$. Therefore we should find all of these variables from given $n, x, y$.

Looking at some assert statements, it seems that `assert x1 ** 2 + e * y1 ** 2 == n` has very important information.
But these values are vectorized as $x = (x_1, x_2)$ and $y = (y_1, y_2)$ and then these vectors are rotated unknown $\theta$.
How can we use this?

## Solution

### Recover $e$

Matrix rotation preserves the norm of a vector.
It means that $x_1^2 + x_2^2$ and $y_1^2 + y_2^2$ are unchanged before and after rotation.

Adding $x_1^2 + ey_1^2 = n$ and $x_2^2 + ey_2^2 = n$, we can obtain an equation:

$$
\begin{align*}
(x_1^2 + x_2^2) + e(y_1^2 + y_2^2) &= 2n \\
\therefore e &= \frac{2n - (x_1^2 + x_2^2)}{y_1^2 + y_2^2}
\end{align*}
$$

Note that the floating points of $x, y$ are enough to recover $e$.

### Recover $p, q$

Please refer to [this article](http://zakuski.utsa.edu/~jagy/Brillhart_Euler_factoring_2009.pdf).
In Theorem 2, it explains how to factor $N$ when we know $a, b, c, d$ such that $N = ma^2 + nb^2 = mc^2 + nd^2$.
Remark that we don't necessarily need to know $m, n$.
The factor can be found by simply calculating $\gcd(N, ad-bc)$.
This means that in the challenge we can calculate $p, q$ by $\gcd(n, x_1 y_2 - x_2 y_1)$.
Even though we don't know $x_1, y_1, x_2, y_2$ at this point, we can calculate $x_1 y_2 - x_2 y_1$ directly since rotation preserves the determinant of a matrix.
(Recall that $AB = C \implies \det(A) \det(B) = \det(C)$ and $\det(R) = 1$.)
Because of floating point, we need to calculate $x_1 y_2 - x_2 y_1$ by [Coppersmith method](https://en.wikipedia.org/wiki/Coppersmith_method).

```python
d = x[0] * y[1] - x[1] * y[0]
PR.<offset> = PolynomialRing(Zmod(n))
f = int(d) + offset
tmp = int(int(d) + f.small_roots(beta=0.495, epsilon=0.03)[0])
p = int(gcd(n, tmp))
assert n % p == 0
q = n // p
```

### Recover $x_1, y_1, x_2, y_2$

Please refer to [this article](https://people.math.carleton.ca/~williams/papers/pdf/202.pdf).
Hardy-Muskat-Williams algorithm in it is useful to recover $x_1, y_1, x_2, y_2$.
