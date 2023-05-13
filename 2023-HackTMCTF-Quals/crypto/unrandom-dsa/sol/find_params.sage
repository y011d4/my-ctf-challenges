# Find q = p1 * p2 * p3 that passes lucas test.
# https://eprint.iacr.org/2018/749.pdf
while True:
    k2 = randint(50000, 50100) * 2 + 1
    k3 = randint(1, 100) * 2 + k2
    if k2 % 5 == 0 or k3 % 5 == 0:
        continue
    if gcd(k2, k3) != 1:
        continue
    MOD = k2 * k3 * 20
    r = crt([7, pow(k3, -1, k2), pow(k2, -1, k3)], [20, k2, k3])
    i = int((2 ** 159 // (k2 * k3)) ** (1/3)) // MOD - 1
    p1 = MOD * i + r
    p2 = k2 * (p1 + 1) - 1
    p3 = k3 * (p1 + 1) - 1
    if p2 % 5 not in [2, 3] or p3 % 5 not in [2, 3]:
        continue
    while True:
        i += 1
        p1 = MOD * i + r
        if not is_prime(p1):
            continue
        p2 = k2 * (p1 + 1) - 1
        p3 = k3 * (p1 + 1) - 1
        n = p1 * p2 * p3
        if n.nbits() < 160:
            continue
        if n.nbits() > 160:
            break
        if not is_prime(p2) or not is_prime(p3):
            continue
        Z = Zmod(n)
        # this check is needed for Miller-Rabin test
        if len(Z(1).nth_root((n - 1) // 2, all=True)) == 1:
            continue
        break
    if n.nbits() == 160:
        break
q = n
Z = Zmod(q)
a = Z(1).nth_root((q - 1) // 2)
# for example:
# k2 = 100063
# k3 = 100071
# q = 898886696987234192216203179809052471733122879407
# a = 863882519526477315572070417818352889307249769025

# find p
p = q
p *= 2 ** (1000 - 160)
i = 2 ** 1023 // p
if p * i % 2 == 1:
    i += 1
while True:
    tmp_p = p * i + 1
    if is_prime(tmp_p):
        break
    i += 2
p = tmp_p
# for example:
# p = 89886145207720563379076109314700840194820575194190016778897807853613605422485207112259455267253174379429416949658020311750500866188971162847593088772574932385403822778600636103214411195158609766347405029879531612592225212154581969576420234887608864928862740452970115309259464332414177760633689253000207400961

# find g
h = 2
q1 = factor(q)[0][0]
while True:
    g = pow(h, (p - 1) // q1, p)
    if g != 1 and pow(g, q1, p) == 1:
        break
    h += 1
# for example:
# g = 30824352989438482732735077095457092561172570076540978194091531991516885846045530429320086099786167050882603115048325168892448057735984440493063219504584969332960618851693308917601032694219338089202582275298750752218804981248600368993996271510285748347372559133454009671037763641622976151384966463882048695452
