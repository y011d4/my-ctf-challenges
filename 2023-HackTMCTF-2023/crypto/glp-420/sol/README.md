# GLP420

## Overview

This is the re-implementation of [GLP](https://en.wikipedia.org/wiki/Ring_learning_with_errors_signature) (or GLYPH), except that modulo polynomial $\Phi(x) = x^{420} - 1$ is modified (strictly speaking there are slight differences like rounding function).
It is believed that GLP is cryptographically secure, but in this case is it exploitable?

## Solution

Since the modified $\Phi(x)$ is suspicious, look into it.
You can easily see that $\Phi(x)$ is factored in $\Z[x]$ into some polynomials:

$$
\begin{align*}
&\Phi(x) = \\
& (x - 1) \cdot (x + 1) \cdot (x^{2} - x + 1) \cdot (x^{2} + 1) \cdot (x^{2} + x + 1) \cdot (x^{4} - x^{3} + x^{2} - x + 1) \cdot (x^{4} - x^{2} + 1) \\
& \cdot (x^{4} + x^{3} + x^{2} + x + 1) \cdot (x^{6} - x^{5} + x^{4} - x^{3} + x^{2} - x + 1) \cdot (x^{6} + x^{5} + x^{4} + x^{3} + x^{2} + x + 1) \\
& \cdot (x^{8} - x^{7} + x^{5} - x^{4} + x^{3} - x + 1) \cdot (x^{8} - x^{6} + x^{4} - x^{2} + 1) \cdot (x^{8} + x^{7} - x^{5} - x^{4} - x^{3} + x + 1) \\
& \cdot (x^{12} - x^{11} + x^{9} - x^{8} + x^{6} - x^{4} + x^{3} - x + 1) \cdot (x^{12} - x^{10} + x^{8} - x^{6} + x^{4} - x^{2} + 1) \\
& \cdot (x^{12} + x^{11} - x^{9} - x^{8} + x^{6} - x^{4} - x^{3} + x + 1) \cdot (x^{16} + x^{14} - x^{10} - x^{8} - x^{6} + x^{2} + 1) \\
& \cdot (x^{24} - x^{23} + x^{19} - x^{18} + x^{17} - x^{16} + x^{14} - x^{13} + x^{12} - x^{11} + x^{10} - x^{8} + x^{7} - x^{6} + x^{5} - x + 1) \\
& \cdot (x^{24} + x^{22} - x^{18} - x^{16} + x^{12} - x^{8} - x^{6} + x^{2} + 1) \\
& \cdot (x^{24} + x^{23} - x^{19} - x^{18} - x^{17} - x^{16} + x^{14} + x^{13} + x^{12} + x^{11} + x^{10} - x^{8} - x^{7} - x^{6} - x^{5} + x + 1) \\
& \cdot (x^{48} - x^{47} + x^{46} + x^{43} - x^{42} + 2x^{41} - x^{40} + x^{39} + x^{36} - x^{35} + x^{34} - x^{33} + x^{32} - x^{31} - x^{28} - x^{26} \\
& - x^{24} - x^{22} - x^{20} - x^{17} + x^{16} - x^{15} + x^{14} - x^{13} + x^{12} + x^{9} - x^{8} + 2x^{7} - x^{6} + x^{5} + x^{2} - x + 1) \\
& \cdot (x^{48} + x^{46} - x^{38} - x^{36} - x^{34} - x^{32} + x^{28} + x^{26} + x^{24} + x^{22} + x^{20} - x^{16} - x^{14} - x^{12} - x^{10} + x^{2} + 1) \\
& \cdot (x^{48} + x^{47} + x^{46} - x^{43} - x^{42} - 2x^{41} - x^{40} - x^{39} + x^{36} + x^{35} + x^{34} + x^{33} + x^{32} + x^{31} - x^{28} - x^{26} \\
& - x^{24} - x^{22} - x^{20} + x^{17} + x^{16} + x^{15} + x^{14} + x^{13} + x^{12} - x^{9} - x^{8} - 2x^{7} - x^{6} - x^{5} + x^{2} + x + 1) \\
& \cdot (x^{96} - x^{94} + x^{92} + x^{86} - x^{84} + 2x^{82} - x^{80} + x^{78} + x^{72} - x^{70} + x^{68} - x^{66} + x^{64} - x^{62} - x^{56} - x^{52} \\
&- x^{48} - x^{44} - x^{40} - x^{34} + x^{32} - x^{30} + x^{28} - x^{26} + x^{24} + x^{18} - x^{16} + 2x^{14} - x^{12} + x^{10} + x^{4} - x^{2} + 1)
\end{align*}
$$

Let these factors to be $\phi_i(x)$.
If we divide $s(x), e(x)$ by $\phi_i(x)$, the coefficients of remainder polynomial are still very small.
This means that we can recover $s(x) \mod \phi_i(x)$ by LLL and then recover $s(x) \mod \Phi(x)$ by CRT, because the degree of $\phi_i(x)$ is relatively smaller.
