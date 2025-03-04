import os
import signal
from secrets import randbelow

from Crypto.Util.number import isPrime

flag = os.getenv("FLAG", "SECCON{this_is_not_a_flag}")


if __name__ == "__main__":
    signal.alarm(120)

    p = int(input("Your favorite prime (hex) > "), 16)
    if not isPrime(p):
        print("p must be a prime")
        exit()

    g = p // 2
    h = p // 3
    x = randbelow(2**512)
    r = (pow(g, x, p) + pow(h, x, p)) % p
    print(f"{r = }")

    guess_x = int(input("Guess x > "))
    if x == guess_x:
        print(flag)
    else:
        print("Wrong...")
