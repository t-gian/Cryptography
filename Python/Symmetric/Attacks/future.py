import requests
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time


def makeDays(n: int) -> int:
    return n * 24 * 60 * 60


session = requests.Session()
my_time = int(time.time())
res = session.get("http://130.192.5.212:6522/login?username=a&admin=1")

date = my_time + 30 * 24 * 60 * 60 # offset expire same as server -> xor to get the keystream
pt_date = str(date).encode()

res = json.loads(res.content.decode())
nonce = int(res["nonce"])
cookie = int(res["cookie"])
cookie = long_to_bytes(cookie)
#len 10
ct_date = cookie[19:29]

for i in range((290 - 256), (300 - 20)): # 300 - [10,266] -> abs([290, 34]) && abs([24,280]) -> [24; 290]
    want_date = str(my_time + makeDays(i)).encode()
    bait = bytearray()
    for w, c, p in zip(want_date, ct_date, pt_date):
        bait.append(w ^ c ^ p)
    new_cookie = cookie[:19] + bait + cookie[29:]
    new_cookie = bytes_to_long(new_cookie)

    res = session.get(
        f"http://130.192.5.212:6522/flag?nonce={nonce}&cookie={new_cookie}")
    if (res.content != b"You have expired!"):
        print(res.content)
        break
