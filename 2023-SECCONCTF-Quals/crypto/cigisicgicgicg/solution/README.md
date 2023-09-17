# CIGISICGICGICG

## Solution

Let $i$-th output of $j$-th inversive congruential generator (ICG) be $x^{(j)}_i$ and $i$-th output of compound inversive generator (CIG) be $z_i$.
Considering $\mod p_1$, $\mod p_2$ and $\mod p_3$, you can obtain the following equation:

```math
\begin{align*}
z_i &= x^{(1)}_i p_2 p_3 \mod p_1 \\
z_i &= x^{(2)}_i p_3 p_1 \mod p_2 \\
z_i &= x^{(3)}_i p_1 p_2 \mod p_3 \\
\end{align*}
```

In the following only $\mod p_1$ is considered without loss of generality.
Let $z_i = 2^L k_i + r_i$ where $r_i$ is known parts ($\approx$ 256 bits) and $k_i$ is unknown parts ($\approx$ 117 bits).
Substituting it for the equation above, you can obtain the following equation:

```math
x^{(1)}_i = (k_i + 2^{-L} r_i) (p_2 p_3)^{-1} 2^L \mod p_1
```

Since $a_1/x_i + b_1 = x_{i+1} \implies a_1 + b_1 x_i = x_i x_{i+1}$,

```math
\begin{align*}
&a_1 + b_1 r_i (p_2 p_3)^{-1} - r_i r_{i+1} (p_2 p_3)^{-2} \\
+&(b_1 (p_2 p_3)^{-1} 2^L - r_{i+1} (p_2 p_3)^{-2} 2^L) k_i \\
-&r_i (p_2 p_3)^{-2} 2^L k_{i+1} \\
-&(p_2 p_3)^{-2} 2^{2L} k_i k_{i+1} \\
=&0 \mod p_1
\end{align*}
```

You can regard this as a linear equation of $k_i, k_{i+1}, k_i k_{i+1}$.
Then, you can construct a lattice $M$ by $N$ equations:

```math
(
\underbrace{0, \cdots, 0}_{3N}, k_1, \cdots, k_{N+1}, k_1 k_2, \cdots, k_N k_{N+1}, 1
) = \boldsymbol{v} M
```

where

```math
\begin{align*}
\boldsymbol{v} &= (
l^{(1)}_1, \cdots, l^{(1)}_{M}, l^{(2)}_1, \cdots, l^{(2)}_{M}, l^{(3)}_1, \cdots, l^{(3)}_{M}, k_1, \cdots, k_{N+1}, k_1 k_2, \cdots, k_N k_{N+1}, 1
) \\
M &= \left(
\begin{array}{cccccccccccc}
-p_1 & \cdots & 0 & 0 & \cdots & 0 & 0 & \cdots & 0 & 0 & \cdots & 0 \\
\vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots \\
0 & \cdots & -p_1 & 0 & \cdots & 0 & 0 & \cdots & 0 & \vdots & \vdots & \vdots \\
0 & \cdots & 0 & -p_2 & \cdots & 0 & 0 & \cdots & 0 & \vdots & \vdots & \vdots \\
\vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots \\
0 & \cdots & 0 & 0 & \cdots & -p_2 & 0 & \cdots & 0 & \vdots & \vdots & \vdots \\
0 & \cdots & 0 & 0 & \cdots & 0 & -p_3 & \cdots & 0 & \vdots & \vdots & \vdots \\
\vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots \\
0 & \cdots & 0 & 0 & \cdots & 0 & 0 & \cdots & -p_3 & 0 & \cdots & 0 \\
b_1 (p_2 p_3)^{-1} 2^L - r_2 (p_2 p_3)^{-2} 2^L & \cdots & 0 & b_2 (p_3 p_1)^{-1} 2^L - r_2 (p_3 p_1)^{-2} 2^L & \cdots & 0 & b_3 (p_1 p_2)^{-1} 2^L - r_2 (p_1 p_2)^{-2} 2^L & \cdots & 0 & 1 & \cdots & 0 \\
-r_1 (p_2 p_3)^{-2} 2^L & \cdots & 0 & -r_1 (p_3 p_1)^{-2} 2^L & \cdots & 0 & -r_1 (p_1 p_2)^{-2} 2^L & \cdots & 0 & \vdots & \vdots & \vdots \\
\vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots \\
0 & \cdots & b_1 (p_2 p_3)^{-1} 2^L - r_{N+1} (p_2 p_3)^{-2} 2^L & 0 & \cdots & b_2 (p_3 p_1)^{-1} 2^L - r_{N+1} (p_3 p_1)^{-2} 2^L & 0 & \cdots & b_3 (p_1 p_2)^{-1} 2^L - r_{N+1} (p_1 p_2)^{-2} 2^L & \vdots & \vdots & \vdots \\
0 & \cdots & -r_N (p_2 p_3)^{-2} 2^L & 0 & \cdots & -r_N (p_3 p_1)^{-2} 2^L & 0 & \cdots & -r_N (p_1 p_2)^{-2} 2^L & \vdots & \vdots & \vdots \\
-(p_2 p_3)^{-2} 2^{2L} & \cdots & 0 & -(p_3 p_1)^{-2} 2^{2L} & \cdots & 0 & -(p_1 p_2)^{-2} 2^{2L} & \cdots & 0 & \vdots & \vdots & \vdots \\
\vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots \\
0 & \cdots & -(p_2 p_3)^{-2} 2^{2L} & 0 & \cdots & -(p_3 p_1)^{-2} 2^{2L} & 0 & \cdots & -(p_1 p_2)^{-2} 2^{2L} & \vdots & \vdots & \vdots \\
a_1 + b_1 r_1 (p_2 p_3)^{-1} - r_1 r_2 (p_2 p_3)^{-2} & \cdots & a_1 + b_1 r_N (p_2 p_3)^{-1} - r_N r_{N+1} (p_2 p_3)^{-2} & a_2 + b_2 r_1 (p_3 p_1)^{-1} - r_1 r_2 (p_3 p_1)^{-2} & \cdots & a_2 + b_2 r_N (p_3 p_1)^{-1} - r_N r_{N+1} (p_3 p_1)^{-2} & a_3 + b_3 r_1 (p_1 p_2)^{-1} - r_1 r_2 (p_1 p_2)^{-2} & \cdots & a_3 + b_3 r_N (p_1 p_2)^{-1} - r_N r_{N+1} (p_1 p_2)^{-2} & 0 & \cdots & 1
\end{array}
\right)
\end{align*}
```

Such an l.h.s can be recovered by LLL algorithm (you need the normalization).
Therefore you can recover the state of CIG.
