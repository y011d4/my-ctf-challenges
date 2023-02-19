# unrandom DSA

## Overview

This is a simple implementation of DSA using pycryptodome's DSA.
What's unique is that `os.urandom` (= `/dev/urandom`) is replaced with python's `random`, which internally uses [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) and we can specify the seed of it.
How can we exploit it?

## Solution

The security of DSA is based on hardness of discrete log problem (DLP).
To break it, we must solve DLP somehow.
DLP can be solved by [Pohlig-Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) when the order is factored to relatively smaller primes (up to around 50 bits).
In DSA, the order is `q`, which is a 160bit prime, that's why DSA is safe.

But the situation is better (worse) because there is no randomness in checking whether `q` is a prime.
Since we can specify `seed`, the output pseudorandom numbers can be controlled (I'll explain later).

In `DSA.construct`, `test_probable_prime` is called.
Here there are two tests for primality, [Miller-Rabin test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test) and [Lucas test](https://en.wikipedia.org/wiki/Lucas_primality_test).
We should make a pseudoprime passing these tests.
Remark that it's said that there is no pseudo prime that passes both of two tests, but this satisfies only when randomness really works.

### Pass Miller-Rabin test

Let $n$ is an integer for primality test and $n - 1 = 2^s d$ where $d$ is an odd number.
In Miller-Rabin test for $n$, we generate $a$ randomly and check whether $a^d \ne 1 \mod n$ and $a^{2^rd} \ne -1 \mod n (0 \le r \le s - 1)$.
If this holds $n$ is a composite.
Therefore if we can control $a$ by seed so that $a^d = 1$ (for example), $n$ is judged as a prime.

### Pass Lucas test

Please refer to [this article](https://eprint.iacr.org/2018/749.pdf).
In this article, there is a way to generate pseudoprime passing Lucas test, which is a composite of three primes.
Please also see my script `find_params.py`.

Note that the generated pseudoprime is $3 \mod 4$.
So we should check whether there are non-trivial solution for $x^{(n - 1)/2} = 1 \mod n$ in order to pass Miller-Rabin test.
$a$ in Miller-Rabin test should be one of these roots.

### Select parameters for DSA

If you can find $q = q_1q_2q_3$ such that:
- $q$ passes Lucas test
- $x^{(q - 1)/2} = 1 \mod q$ has non-rivial solutions
- $q_i$ is prime
- $q_1 < q_2 < q_3$, $q_1$ is around 40bits
- $q$ is 160bits

you can then determine $p$ and $g$ which are exploitable. 
$p$ can be determined by randomly generating an integer $k$ and checking $p = qk + 1$ is a prime.
It is recommended that $k$ compose of many small primes so that sage's `discrete_log` works fast.
$g$ should be $g^{q_1} = 1 \mod p$ in order to solve DLP by Pohlig-Hellman algorithm.
Note that such $g$ also satisfies $g^q = 1 \mod p$, which is required by DSA.
This can be found by $g = k^{(p - 1) / q_1} \mod p$ where $k$ is a random number.

### Generate pseudorandom numbers as intended

This part is inspired by the recent interesting challenge, [janken vs kurenaif](https://ctftime.org/task/23986) in [SECCON CTF 2022 Quals](https://ctftime.org/event/1764).

In `pycryptodome`, if `randfunc` is not specified, `os.urandom` (`/dev/urandom`) is used.
But in this challenge it is replaced with python's `random.randbytes`.

Python's `random` uses [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) (MT).
In MT, there are 624 states of 32bits.
Random numbers are generated from the state by temper operation (See [here](https://github.com/python/cpython/blob/main/Modules/_randommodule.c#L150-L154)).
The most important for this challenge is state is generated from seed (See [here](https://github.com/python/cpython/blob/main/Modules/_randommodule.c#L349) and [here](https://github.com/python/cpython/blob/main/Modules/_randommodule.c#L208-L233)).
We can find by SMT solver like z3py a seed that generates expected successive random numbers.
