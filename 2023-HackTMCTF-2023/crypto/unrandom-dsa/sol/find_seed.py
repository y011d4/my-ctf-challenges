import os
import random
# urandom is unrandom
os.urandom = random.randbytes
from z3 import *
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import DSA


N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF


def bit_shift_right_xor_rev(x, shift):
    i = 1
    y = x
    while i * shift < 32:
        if type(y) == int:
            z = y >> shift
        else:
            z = LShR(y, shift)
        y = x ^ z
        i += 1
    return y


def bit_shift_left_xor_rev(x, shift, mask):
    i = 1
    y = x
    while i * shift < 32:
        z = y << shift
        y = x ^ (z & mask)
        i += 1
    return y


def untemper(x):
    x = bit_shift_right_xor_rev(x, 18)
    x = bit_shift_left_xor_rev(x, 15, 0xEFC60000)
    x = bit_shift_left_xor_rev(x, 7, 0x9D2C5680)
    x = bit_shift_right_xor_rev(x, 11)
    return x


def update_mt(mt):
    new_mt = mt.copy()
    for kk in range(N - M):
        y = (new_mt[kk] & UPPER_MASK) | (new_mt[kk + 1] & LOWER_MASK)
        if type(y) == int:
            new_mt[kk] = new_mt[kk + M] ^ (y >> 1) ^ (y % 2) * MATRIX_A
        else:
            new_mt[kk] = new_mt[kk + M] ^ LShR(y, 1) ^ (y % 2) * MATRIX_A
    for kk in range(N - M, N - 1):
        y = (new_mt[kk] & UPPER_MASK) | (new_mt[kk + 1] & LOWER_MASK)
        if type(y) == int:
            new_mt[kk] = new_mt[kk + (M - N)] ^ (y >> 1) ^ (y % 2) * MATRIX_A
        else:
            new_mt[kk] = new_mt[kk + (M - N)] ^ LShR(y, 1) ^ (y % 2) * MATRIX_A
    y = (new_mt[N - 1] & UPPER_MASK) | (new_mt[0] & LOWER_MASK)
    if type(y) == int:
        new_mt[N - 1] = new_mt[M - 1] ^ (y >> 1) ^ (y % 2) * MATRIX_A
    else:
        new_mt[N - 1] = new_mt[M - 1] ^ LShR(y, 1) ^ (y % 2) * MATRIX_A
    return new_mt


def random_seed(seed):
    init_key = []
    if isinstance(seed, int):
        while seed != 0:
            init_key.append(seed % 2 ** 32)
            seed //= 2 ** 32
    else:
        init_key = seed
    key = init_key if len(init_key) > 0 else [0]
    keyused = len(init_key) if len(init_key) > 0 else 1
    return init_by_array(key, keyused)


def init_by_array(init_key, key_length):
    s = 19650218
    mt = [0] * N
    mt[0] = s
    for mti in range(1, N):
        if isinstance(mt[mti - 1], int):
            mt[mti] = (1812433253 * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti) % 2 ** 32
        else:
            mt[mti] = (1812433253 * (mt[mti - 1] ^ LShR(mt[mti - 1], 30)) + mti)
    i = 1
    j = 0
    k = N if N > key_length else key_length
    while k > 0:
        if isinstance(mt[i - 1], int):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525)) + init_key[j] + j) % 2 ** 32
        else:
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ LShR(mt[i - 1], 30)) * 1664525)) + init_key[j] + j)
        i += 1
        j += 1
        if i >= N:
            mt[0] = mt[N - 1]
            i = 1
        if j >= key_length:
            j = 0
        k -= 1
    for k in range(1, N)[::-1]:
        if isinstance(mt[i - 1], int):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941)) - i) % 2 ** 32
        else:
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ LShR(mt[i - 1], 30)) * 1566083941)) - i)
        i += 1
        if i >= N:
            mt[0] = mt[N - 1]
            i = 1
    mt[0] = 0x80000000
    return mt


def find_seed(rands):
    assert len(rands) <= N
    for i in range(len(rands)):
        assert 0 <= rands[i] < 2 ** 32
    state = [BitVec(f"state_{i}", 32) for i in range(N)]
    next_state = update_mt(state)
    s = Solver()
    s.add(state[0] == 0x80000000)
    for i in range(len(rands)):
        s.add(next_state[i] == untemper(rands[i]))
    s.check()
    m = s.model()
    state = [m[s].as_long() if m[s] is not None else 0 for s in state]

    seed = [BitVec(f"seed_{i}", 32) for i in range(N)]
    mt = random_seed(seed)
    s = Solver()
    for i in range(N):
        s.add(mt[i] == state[i])
    s.check()
    m = s.model()
    seed = [m[s].as_long() for s in seed]

    seed_int = 0
    for s in seed[::-1]:
        seed_int *= 2**32
        seed_int += s
    return seed_int


q = 898886696987234192216203179809052471733122879407
a = 863882519526477315572070417818352889307249769025
p = 89886145207720563379076109314700840194820575194190016778897807853613605422485207112259455267253174379429416949658020311750500866188971162847593088772574932385403822778600636103214411195158609766347405029879531612592225212154581969576420234887608864928862740452970115309259464332414177760633689253000207400961
g = 30824352989438482732735077095457092561172570076540978194091531991516885846045530429320086099786167050882603115048325168892448057735984440493063219504584969332960618851693308917601032694219338089202582275298750752218804981248600368993996271510285748347372559133454009671037763641622976151384966463882048695452


rands = []
# First, Miller-Rabin test is done 4 times for p
for _ in range(4):
    # randbytes(1) is called once. value is arbitrary as long as it's less than p's highest byte.
    rands += [0x33 << 24]
    # After that, randbytes(127) is called
    # Since 127 * 8 = 1016, getrandbits(1016) is called.
    # 1016 = 32 * 31 + 24
    # The following values are arbitrary
    rands += [0x1337] * 31
    rands += [0x1337 << 8]
# Second, Miller-Rabin test is done 30 times for q
# Random numbers should be a - 2 all the time.
a_bytes = long_to_bytes(a - 2)
for _ in range(30):
    # randbytes(1) is called once. value is arbitrary as long as it's less than p's highest byte.
    rands += [a_bytes[0] << 24]
    # After that, randbytes(19) is called
    # Since 19 * 8 = 152, getrandbits(152) is called.
    # 152 = 32 * 4 + 24
    for i in range(1, 17, 4):
        rands += [a_bytes[i] + a_bytes[i+1] * 256 + a_bytes[i+2] * 256**2 + a_bytes[i+3] * 256**3]
    rands += [(a_bytes[17] + a_bytes[18] * 256 + a_bytes[19] * 256 ** 2) << 8]

seed_int = find_seed(rands)
# for example:
# seed_int = 0x5f234753fcbde3ac4e99c253069a7f85b9a57eeaa28472303b6494957f26a3272f6cbe488962623da7d7d0802292b684070484bef9547f444feb8b9a0955bf719497fa09c75649006e5cec00eb2b9a4e0fb13cdaae7c22d0b8774bee2f78d4ffbeee382c470f410c74cc473e46d027d1782ee4844866242fabf434badc96ec5fa7b93da296c37b76cde8ae86361fd0765f0b9f84dfc38adfcd61c81f3ff48368c979ba30f26eec85f6db9c5363c76452a85afd56b95fea633edc8c96641b247aca46ce4e0e1e00ed8a314b5a8225296fc0b8d62313ae91b3d1f6272b4f133471735d49a4505fe009ccb55a18993b58511e4d903fc82bc6bea565e7aed9e23d91df7ffbbedf7cceebca9ed8cebabea768f7b62878be2c2e6b8c1e7870e22c85be0eee0fd11410382d742e4e303aac1a5b6850072264ac5ab7aa7adc6704422e4c3f024364af95887e4f3f6c858dafe9c046e89535c763f17c211c7c066cb0f62214595aafd647fa8f80aae3f52b15f25d76ebd316237bc70512e7786a76c826a250a992d10f66db2761f84af0072690c98f644d97ff15cd9deb1364794392e2386fd9881abd77ada23bb4e822ed0214b0f2a318915e0a497400101953930f2e1f089ea01e6d505847d36fef4526b55cf38cae13af7dedab2b710aeaca11ef816f089c86057dd94dff4e7d9d20758ebcacd37ea0381929c86fe3da93cbd9d9f6f889b6e8436832817cea92c823097b7c62b8c3f4070513ae47264ee55184d14d1897954e138cdb9f0501a52cc76dc8cb41c33a8ca49243e85e79e662449f88e18e763c69811762e84d7db7d5f58d1f780228193a9e00435a717de467fe47be4f45716c1d8db65cb122221190660a404cc5206787881204778aada0ceb1bf574806bdc65e161fc7dd44a9e84f7076750b5febd0258a253b78adcda028e7fe0a4241dacb15d45d137d8b0d4ce905e81f73c7fc9cd53473f316e2bf04355b2e635dde359e7dd37b96cbfa394830e55f2577442b23fbe76ba041d56559591fa21140ffad487447843c86d529670449d4b748578e329813dba54a2e1db11ffaf0a93ce2c63eb77b3e67a06c69922b23db4d70c2dc6921f74602f5e250c689348c5c8ed44b25e8419dcbcc07c9af1c1f97c72e579bf445446f9da37460f7d3bc8eed38ffda80399aaca5cf12f303388bf364930a455f495355a20222738d4f435818adb983d4e647718d67651d824e1e471a0d0b53b7bb46460547210ce23f6215b4a69301a11b4bc7391f2ad83aa4f44ff381eeb36bf4e1786acb9a1d8780dd003cf3317deeb1a717bf2f39540d1931003958693ea2b3420eb11a6407969647a0512f710f4cbb6e80f7487a22eff221a8d92cafbc25984e07077320aa0a29a5ed86d976dffffde8f1329395ec395f73b12a53d1dee3325d630806a67a91fd884dd08aa9f4d7b3f9de82357819fd5387e2f3e2247945efb87302f8af8dcb194c26ecc68c2f0cfc85bb567e25357916f471c42aa90570a0a299412ee2e0eeee4a90959388c1aeb7f612ce5724f6a77f4ca4bb654698a7f05523873fe70b9537529147ff18d476f34e87121e22537358500acf037c276b4d39e58e5a1c017c572f1ed4d5d74d2c3ccda2006b55e31246bb4770906e5ab3f3ea3f2187a429c3438fc27ae570bf39fb576ad70448a5519e51bbc81a878429790eb8500ab63cf07b0913dca24d291d7dfa63662e415859eb013103f5d1bd5072940b9177922c9c560c13dbc175a57fb7ba1400a446736b6a8604617af458e626353e84027796b2a97e1560700018f93bd5ae5ebf411ec4818db764198f82212de8346e2f03d8a1ca39f00d0d1e34e31acb89541c1a3887d7762527bc6e81693dbe74ab0c3fa03292dd63291b228f0ea45d1e1db7892af47da6d2f3737bc970326301d077ec484050c03fb0ea11f67d9a9db28b8ce13f1e4b252d2a07dd576d400bc8e63cb6d7e9b7646aba7fe7636fc209ef8618eefef74b69212d3817d702d08b66e1c2484f626f761c48e32ce789ccb0d911e52be5660a9c74bc93d55904e9c1f85e3094b07fa1d1afa48012b72546658df76561cd66f3ff8fbc9fc1785c36270fdafddba089ef02cdfb7dbb8b5f22fea852b9e061462fc868a89add5ccd6c6fe5ee12226bb1ae50fb00c10b825dc43820710478c31efa35b2b7844fae561c8eb430766cbd35f1f2283e27f4d79757144bb341793a37240c1676d30c1c3541fba2fabf227af20713e7b4cd7790fac52ac659de002b39b2d65b037565d8ff0254d507a54def35f0cd41ec6a2e0ab5078764cf5dad6331863de8fc644b54b63c9bb314051f2850c62c1f306ded13901a79f09dfd0031e8a34aceab7e8aa967155954a081b2ae05b36c4de40cd58dfade80a4ac793ded43a5dbf5f12d82ada9b88b667ecbe0722f1bb832074f332f799642a90c3f80ac23c22cece4ed0bbeacd49a0c327134bf83fdde7545f968dce636bfadcf0e7318c70dfcdcc0346d70c96cc36d75752822fa00d69d819fe6c6d13e20de24dab8798c3eb5f9c2f9259de7118b431300cee257ab344711f437b26ab64c8a41f91ddc7594b1773b99aaa2e23a27cba29de646950b26d381816a2d76bee0ee075798ce2199de16fb1741f9e2614b285b20f8032d33ec98f89565588409d5b000750318db2af0bdf8f60aa0c42b1f5d76c28b75229e002486cb6b372226d210f711fc4177505f99ffec9fae559610807bbda123e5fed57f5751b34051f2023df359f90cec1d74058aa23abb474762c63aefe05b7cd0668357c89baffda672810afff052621e1a38a8dda3c406bb1c54f6c7b2e44f3a174c8a1a8ecb051a3197eddbb7a970c3e858c279016595d6cea1244afa4a9db042eb48df24c2e0816da446b7071482b09330fe7aaa7f0fb4fa729ba37174d7b8e4ac1f0ac9140d5c364b69c49e3930efe06cdda4c80f66a3386ca680cb09e08852fea5aac594fe9f119b9bd9cc5a3d4c84c5a1ca192f09ac89e5a9825ebd6998a4b2384757ce325277b597b18242eb85c559bd6cbcffbaab82021dc3b8159cc6f5d9dc1b35efc4f4075cd2784213651d5424b676e4b2f28e47541ed3e3413ea90e8feb41ec01401119d17c2cb514eeed56d5fa4d66cccabc835e43924a2ecb786c2cbc650295d69da7e5e69503aaed1f34d928fcd255645cb62fd5ed56aeea5560aed3f8068cb76d25c03ed7f2d903434aa263bef4b66d324e136e6edea6b59bfbd7a766a98d0cbed15a1a59a67f3db24a99315abd16b6ddc22579e07bd8aa17e86d6414cbe2f2d23968319c4f36febae2f4df3839ebdfb77417fb0a3e0c500549fff8bb2f4d13059c879872924e0aeea51882a9c48e9277078a61d6750b2311a8907660f4dc7c3eab7748fde0b7e29ebc02d4fb9b070d2cc8d7ce7f8a6b941c8233d71a25cda904b8b140cb62d684fefe32e35b7470dfd8beaa8ef6bb8ffc7142c01345438e495daca5e4a80d7299e2847bb98a7249844eab786d7781efb683f1bd1f8736

# test
x = random.randint(1, q - 1)
y = pow(g, x, p)
random.seed(seed_int)
# if params and seed are generated correctly, the following doesn't throw any error!
dsa = DSA.construct((y, g, p, q, x))
