# DLP 4.0

## Solution

The maximum order of $g$ is $p^2 - 1$ as indicated in the source code.
So if we can find $p$ such that $p^2 - 1$ is smooth, we can solve discrete log by [Pohlig-Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm).

One way to find such a $p$ is randomly search $x$ such that $p = 2x^12 - 1$ is a prime.
Then, $p + 1 = 2x^12$ is smooth obviously and $p - 1 = 2(x^12-1) = 2(x^4 - x^2 + 1)(x^2 + x + 1)(x^2 - x + 1)(x^2 + 1)(x + 1)(x - 1)$ is smooth with relatively high probability.
