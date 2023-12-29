# KEX 4.0

## Solution

Quaternions are not commutative, this cryptosystem is a variant of [Non-commutative cryptography](https://en.wikipedia.org/wiki/Non-commutative_cryptography). But since quaternions can be represented as a $4 \times 4$ matrix with 4 degrees of freedom (see [here](https://en.wikipedia.org/wiki/Quaternion#Matrix_representations)) almost all equations are linear.

Let `share_A`, `share_B` to be $S_A, S_B$. Then $A S_A = \mathrm{Pub}_B A$. This has 4 equations with 4 variables. However, solving this, you can find 2-dimension kernel. It's insufficient to recover $K$.

In order to reduce the dimension of the kernel, you have to incorporate something.
Recall the RSA 4.0 challenge in the quals. The coefficients of $i, j, k$ of $m^x$ have a same multiple (The proof is [here](https://github.com/y011d4/my-ctf-challenges/tree/main/2023-SECCONCTF-Quals/crypto/rsa-4.0/solution))
Using this fact, the linear equation is solved except for constant multiplication.

Should this constant multiplication be recovered? No, it's because $K = A^{-1} B^{-1} A B$ is not changed by the constant.

In the same way you can recover $B$ sufficiently, which will recover $K$ completely.
