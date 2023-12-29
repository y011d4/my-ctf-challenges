import os

from pwn import remote


def calc_order(g, mult_order, func_pow):
    assert func_pow(g, mult_order) == func_pow(g, 0)
    order = mult_order
    for pi, e in list(factor(order)):
        for i in range(e):
            if func_pow(g, order // pi) == func_pow(g, 0):
                order //= pi
            else:
                break
    return order


def bsgs(g, h, n, func_op, func_pow, func_inv, func_hash):
    m = ceil(sqrt(n))
    table = {}
    tmp = func_pow(g, 0)
    j = 0
    for j in range(m):
        table[func_hash(tmp)] = j
        tmp = func_op(tmp, g)
    factor = func_pow(func_inv(g), m)
    gamma = h
    for i in range(m):
        if func_hash(gamma) in table:
            j = table[func_hash(gamma)]
            ret = i * m + j
            assert func_pow(g, ret) == h
            return ret
        gamma = func_op(gamma, factor)


def pohlig_hellman(g, h, mult_order, func_op, func_pow, func_inv, func_hash):
    assert func_pow(g, mult_order) == func_pow(g, 0)
    a_list = []
    b_list = []
    order = calc_order(g, mult_order, func_pow)
    for pi, e in list(factor(order)):
        gi = func_pow(g, order // pi**e)
        hi = func_pow(h, order // pi**e)
        gamma = func_pow(gi, pi ** (e - 1))
        xk = 0
        for k in range(e):
            hk = func_pow(func_op(func_pow(func_inv(gi), xk), hi), (pi ** (e - 1 - k)))
            dk = bsgs(gamma, hk, pi, func_op, func_pow, func_inv, func_hash)
            xk = xk + pi**k * dk
        xi = xk
        a_list.append(xi)
        b_list.append(pi**e)
    return crt(a_list, b_list)


io = remote("localhost", int(8888))

p = 9687981458160406610617838441628851591635112892879265492650567118367810213451536688262026445800781249
Q = QuaternionAlgebra(Zmod(p), -1, -1)
i, j, k = Q.gens()

io.sendlineafter(b"p: ", str(p).encode())
io.recvuntil(b"g = ")
g = eval(io.recvline().strip().decode())
io.recvuntil(b"h = ")
h = eval(io.recvline().strip().decode())

func_op = lambda x, y: x * y
func_pow = lambda x, y: x**y
func_inv = lambda x: x**-1
func_hash = lambda x: x
mult_order = p**2 - 1

_x = pohlig_hellman(g, h, mult_order, func_op, func_pow, func_inv, func_hash)

io.sendlineafter(b"x: ", str(_x).encode())
flag = io.recvline().strip().decode()
print(flag)
