import jwt
import uuid
import time
import sys
import getopt

pubkeyfilename="public.key"
privkeyfilename="private.key"

# default payload values
sub = "spwr_installer"
iss = "sunpower"
aud = "dev1"
t = 86400
decode = False
kid = "987e3afb-49d2-4c11-bfcf-6a6514261ef7"

options, arguments = getopt.getopt(
    sys.argv[1:],
    's:i:a:t:dk:',
    ["sub=","iss=","aud=","time=","decode","kid="])

for o,a in options:
    if o in ( "-s", "--sub"):
        sub = a
    if o in ( "-i", "--iss" ):
        iss = a
    if o in ( "-a", "--aud" ):
        aud = a
    if o in ( "-t", "--time" ):
        t = int(a)
    if o in ( "-d", "--decode" ):
        decode = True
    if o in ( "-k", "--kid" ):
        kid = a

now = round(time.time())

with open(pubkeyfilename, "r+") as pubkeyfile:
    public_key=pubkeyfile.read()

with open(privkeyfilename, "r+") as privkeyfile:
    private_key=privkeyfile.read()

payload = {
    "sub" : sub,
    "iss" : iss,
    "iat" : now-1,
    "aud" : aud,
    "exp" : now + t,
    "nbf" : now - 120,
    "jti" : str(uuid.uuid4())
}

encoded=jwt.encode(payload, private_key, algorithm="RS256", headers={"kid":kid})
sys.stdout.write(encoded)

if decode:
    decoded = jwt.decode(encoded, public_key, audience=aud, algorithms=["RS256"])
    print(decoded)
