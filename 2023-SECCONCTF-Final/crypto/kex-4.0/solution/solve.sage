from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes


def hash_Q(x):
    return sha256(
        long_to_bytes(int(x[0]))
        + long_to_bytes(int(x[1]))
        + long_to_bytes(int(x[2]))
        + long_to_bytes(int(x[3]))
    ).digest()


def matmul(A, B):
    res = []
    for i in range(4):
        row = []
        for j in range(4):
            tmp = 0
            for k in range(4):
                tmp += A[i][k] * B[k][j]
            row.append(tmp)
        res.append(row)
    return res


def solve(ShareA, PubA, PubB):
    PR = PolynomialRing(Zmod(p), names=[f"a{i}{j}" for i in range(4) for j in range(4)])
    a_list = PR.gens()
    Amat = [[a_list[4*i+j] for j in range(4)] for i in range(4)]
    lhs = matmul(PubB, Amat)
    rhs = matmul(Amat, ShareA)
    polys = []
    for i in range(4):
        for j in range(4):
            polys.append(lhs[i][j] - rhs[i][j])
    for i in range(3):
        polys.append(Amat[0][0] - Amat[i+1][i+1])
    polys.append(Amat[0][1] + Amat[1][0])
    polys.append(Amat[0][1] + Amat[2][3])
    polys.append(Amat[0][1] - Amat[3][2])
    polys.append(Amat[0][2] - Amat[1][3])
    polys.append(Amat[0][2] + Amat[2][0])
    polys.append(Amat[0][2] + Amat[3][1])
    polys.append(Amat[0][3] + Amat[1][2])
    polys.append(Amat[0][3] - Amat[2][1])
    polys.append(Amat[0][3] + Amat[3][0])
    mat = matrix(Zmod(p), len(polys), 16)
    vec = vector(Zmod(p), len(polys))
    for i in range(len(polys)):
        for j, a in enumerate(a_list):
            term = {_a: 1 if _a == a else 0 for _a in a_list}
            mat[i, j] = polys[i].coefficient(term)
            vec[i] = -polys[i].constant_coefficient()
    K = mat.right_kernel_matrix()

    mat = matrix(Zmod(p), 3, 3)
    mat[0] = K[0, 1:4]
    mat[1] = K[1, 1:4]
    mat[2, 0] = PubA[0, 1]
    mat[2, 1] = PubA[0, 2]
    mat[2, 2] = PubA[0, 3]
    vec = vector(Zmod(p), 3)
    tmp = mat.left_kernel_matrix()[0]
    tmp_K = tmp[:2] * K

    i, j, k = Q.gens()
    _A = tmp_K[0] + tmp_K[1] * i + tmp_K[2] * j + tmp_K[3] * k
    return _A


p = 0xC20C8EDB31BFFA707DC377C2A22BE4492D1F8399FFFD388051EC5E4B68B4598B
order = p**2 - 1
Q = QuaternionAlgebra(Zmod(p), -1, -1)
i, j, k = Q.gens()
pub_A = (
    71415146914196662946266805639224515745292845736145778437699059682221311130458
    + 62701913347890051538907814870965077916111721435130899071333272292377551546304 * i
    + 60374783698776725786512193196748274323404201992828981498782975421278885827246 * j
    + 60410367194208847852312272987063897634106232443697621355781061985831882747944 * k
)
pub_B = (
    57454549555647442495706111545554537469908616677114191664810647665039190180615
    + 8463288093684346104394651092611097313600237307653573145032139257020916133199 * i
    + 38959331790836590587805534615513493167925052251948090437650728000899924590900 * j
    + 62208987621778633113508589266272290155044608391260407785963749700479202930623 * k
)
share_A = 57454549555647442495706111545554537469908616677114191664810647665039190180615 + 29676674584636622512615278554619783662266316745243745754583020553342447549066*i + 13738434026348321269316223833101191512670504554293346482813342673413295266974*j + 23943604179074440949144139144245518129342426692024663551007842394683089455212*k
share_B = 71415146914196662946266805639224515745292845736145778437699059682221311130458 + 65071948237600563018819399020079518439338035815171479183947570522190990857574*i + 52272525531848677372993318721896591307730532037121185733047803928301284987593*j + 68406537373378314867132842983264676792172029888604057526079501977599097329576*k
nonce = bytes.fromhex('6ced0927695bc45e')
enc = bytes.fromhex('6a59a899fed260513cd4ad037bb3d8681ae47e4d5c13139aebde981c01f93aac63d6a39c04e4dfa3fd05fa41c1bcda8b39c660aff5673458d5324eac738d1bd0a255')

ShareA = share_A.matrix()
ShareB = share_B.matrix()
PubA = pub_A.matrix()
PubB = pub_B.matrix()
_A = solve(ShareA, PubA, PubB)
_B = solve(ShareB, PubB, PubA)
K = _A**-1 * _B**-1 * _A * _B

key = hash_Q(K)
cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
flag = cipher.decrypt(enc)
print(flag)
