import base64
import hashlib
import time
from pprint import pprint

import jwt
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from fastcrc import crc64

encrypt_key = b"V6h9A_wyEE6YLFiAtxY4W601RkBQIsLn"
send_time = 1733155227
send_tag = int("530673b302e65741", 16)

for actual_time in range(send_time - 30, send_time + 30):
    tag_value = encrypt_key + actual_time.to_bytes(8, "big")
    tag = crc64.ecma_182(tag_value)
    if tag == send_tag:
        break
else:
    raise ValueError("Tag not found")

tag_bytes = tag.to_bytes(8, "big")
mangled_key = bytes(
    [b ^ tag_bytes[i % len(tag_bytes)] for i, b in enumerate(encrypt_key)]
)
cipher = Cipher(ARC4(mangled_key), mode=None, backend=None)

data = bytes.fromhex("""f5628d0dbfcb9222753076
d8
42
24
2e
26
6d
e2
eb
8d
cc
0e
94
b0
d9
cb
35
ce
0f
97
eb
f2
4a
23
4c
00f84a27c0c22d8fb9e42f177ecc6db182aa9b9435bb2cc7269d6801a3be11784c33994c9caaa7ef0966066a7bcc1ab642943c9fdb4e72fbb2ee7604f78b8a17dce10e7e33715c2b745b09f80da2941976fe73b264b8df1f01061a4c6969a870167e4350fa17d42e51a5d3f6a726439f3a730b2d2ef41b4f1159645449f1e4d02c329da18bb24b9e6db04d1923cc1176bf9e7a2209ffa6ed4c62249fc773cc6103b204e84d00096c70205d4a681fe4633ef47f12969735e5e5a4589fb7c6a0c68fa28bd7c9180ebf078b34ef6708981a3977ef8e938b506c52dcbb9c73742dc4080fa71b0c0a6c28fc249978c18fbf7e1dab8534125b8672d9128f52b2da7c26b937b65b2962657e97dd7e89ca51ab114c43e30b6bfeb0ff11730393f869572a60622664afcd4cade34b10e6a9e50e607bcbb235fe1a19a6bbdf81939fe70bdd78161bc6b5096c210120aa0ec1bfa77f3da5dbd13cd828760bb98c28c3ba705fc3e0d8299b099b331ef85e86c8069285fda6b161f3d3950dc4037095ab4c0685e156df9fa26247f71579cd3e477d6a3a83b3db8f9841abcf56b3e817492c57fe4ff598359c6bd9aeb1a32509370cd067bdeef3d5fc6afb800f6be92c97b2669579826e39d189c468bc360f3ab70c6974761a58a5f9a3e3005e5f30c4dd5045b4f41282fa4a16fa41fe12245206634084249923a2ef6a579a5803b3b20e7ca05814f6df291379bce49a91c8e80a60fcf6dff238df2ece628469f1db125727c11428d47d9874f88143fd49276ea376a5cf59bdae210f9b5fc1a86822f0b8f5d857fbe4cb52ab07c64fb7b367e5deac73ae5340f636cbf15699a0e5ab370c0d7d1af6ac7f1fd9ba410b1dda16c33a8d7ed31599c47e0ef7bf0c9bdd14dc4f3d56518dd3b0344b9fc6a86cd3be9e4073e7b45648b0b93422cb8e5d5cc48e249dae60066c81dcbb81c2ee4558bb75985dd03a41c203cdb0ab8cb52b1c4e2362609e777a19d43b73c56ea81c680f60936f1c0736a558f6486c9c2baf23c2f71fbc817e9dbacbd0e442332dde867422f8936dce15bfbcb667cfffead82bf7b28d7fe09ef430abf9b3f5c1119ad7c5e7822f9ddcba713c04ae3ca6b572f3dfb1e6c89bff55e0b99e22dec7cba60648e1fb2cdf24e78e97072c451f946706e705c4f908b07b8efd4dac13a8000fc9f7fe420c5ff03ff6c9bb3f863931d268ae9650213a2f7b29ea13f031d9dfcab9a2e5005d7a4118cd8c1da395f27e0688cb41e9e2e3aff857069e50ea7621a15f0087ad7c4041dc1146530ad03412f3df7c27ef8a118cf9542ffc621d4e9cac4ab1582aad59fa46ff767a30d0a8a5d4ac8524623c5edfcc9a49d54e0189cab1fa9e597636a37ae2d64b017d67e1a41ae834c4a3949037600a
f63fe1
60b17a
77f162
6cfa36
b9c622
a480ca
96601f
101643
7da396
342844
a24639
3a5278
e3b108
e43c1e
f625f9
6ce0d8
1216fc
b23a6a
2c4934
16c9f1
5d75a9
b48ed8
721c61
4115c1
e84722
4d569a
5e41b0
fe0c53
7c0ffc
158a67
09b3c5
42177f
dee3a9
0737ac
39df74
d42438
84378d
b960ca
62eedf
ef07b7
827d51
95
21
eb
a7
e0
ec
40
d4
3c
66
2a
24
98
2a
9f
c5
ad
06
e7
4d
77
6b
d99193
99f62c
5863be
9ff22c
e21ff2
3d0ffc
c50465
16
61
51
2c
f8
57
aa
15
9a
4b
e3
3e
c2
0f
8e
6c
5f
20bfba
c8f59b
7d6b9b
e394f0
d5
7f
f8
68
d1
4d
fe
e0
4f
a1
de
62
3f
90
da
06
a2
e323f2
cb
34
ae
94
38
ca
2c
8e
37
88
3d
a9
fa
b5
dc
10
5f
ab
46
1a
aa
e7
bc
21
3c
14
65
94
af
65
15
d7
92
1a
49
55
88
9b
e7
d0
d7
0f
c9
33
ec
79
8d
d8
f0
6e
07
d6
3e
c16704
7f4433
f9abcf
fb1a4e
57acdc
52fd5d
5e4535
b6ebe5
15f1a8
63a5f5
e5f4ce
db9b75
399481
d4b51a
3b8089
cd0a89
b8703d
4bcea5
a51f8d
9c02c1
de3398
db7ed6
fb1507
bb01d6
051fe1
c90e8c
e4d69b
5544ef
d42026
34c4ad
7ab3bd
6df6f2
0b8998
44c91a
0240dd
ddf54c
a323e9
c5b1b7
f5d4e2
8ecc80
d184d3
adf7eb
9bacfd
f7ea57
5cc5df
d2
b5
85
bd
90
d0
06
71
56
64
57
27
08
a3
82
eb
59
de
5f
b3
97
2b952a
30
49d401
b4
c7
2f
ae
79
92
6a
fb
0b
93
60
b2
b3
45
f8
52
1d
75
b9
79
7c
76
03
ee
bb
d5
cd
bf
be
b2
74
2c
a5
30
ea
32
88
e0
64
04
a1
53""")

pprint(cipher.decryptor().update(data))


jwt_secret_encrypted = base64.b64decode(
    "pp8UBhPveEs2kuoXgDROebXRRYT+mB0Hb8gNMwtD+2NAv5GhaEMlW6CWpCnyW1496LV+Z2952EwbsHDDGFzd1/e6PRkUtqHlOdGKPTXZINZOLI+PbfUckYikgsRjNJPQUdy3pS2Xf/bT5MAsg0piQIUhpCAdmjHpx+ujbnSNhQ=="
)

cipher = Cipher(
    AES(
        hashlib.sha256(
            bytes.fromhex(
                "a86ba5631f1a575d63d8a8d789ed3e68967998fde3d5e2ba035b4e34986715c8"
            )
        ).digest()
    ),
    GCM(jwt_secret_encrypted[:12], jwt_secret_encrypted[12 : 12 + 16]),
    None,
).decryptor()
jwt_secret = cipher.update(jwt_secret_encrypted[12 + 16 :]) + cipher.finalize()
pprint(jwt_secret)

target_jwt = jwt.encode(
    {"uid": 1, "sub": "admin", "role": "admin", "exp": int(time.time()) + 60 * 60 * 24},
    jwt_secret,
    algorithm="HS256",
)
print(target_jwt)
