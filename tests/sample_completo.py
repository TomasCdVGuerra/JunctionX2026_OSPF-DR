# pyright: reportMissingImports=false, reportUndefinedVariable=false, reportAttributeAccessIssue=false

from hashlib import md5, sha1 as s1, sha256, new as hnew
from Crypto.Cipher import AES, DES, DES3, ARC4
from Cryptodome.Cipher import AES as A2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from . import helpers
import hashlib
import hashlib as hl
import Crypto.Cipher.DES
import hmac

# ---------------- hashes: devem ser achados
hashlib.md5(b"a")                                  # EXPECT 1
hl.sha1(b"a")                                      # EXPECT 1  alias de modulo
md5(b"a")                                          # EXPECT 1  from-import
s1(b"a")                                           # EXPECT 1  from-import com alias
hashlib.new("md5")                                 # EXPECT 1
hashlib.new(name="SHA-1")                          # EXPECT 1
hnew("md4")                                        # EXPECT 1
hashlib.md5(b"x", usedforsecurity=False)           # EXPECT 1  com nota
hmac.new(k, m, hashlib.sha1)                       # EXPECT 1  referencia
hmac.new(k, m, "md5")                              # EXPECT 1  string
hmac.new(k, digestmod="sha1")                      # EXPECT 1  keyword
hashlib.pbkdf2_hmac("sha1", p, s, 1000)            # EXPECT 1
hashes.MD5()                                       # EXPECT 1
hashlib.md5(b"a").hexdigest()                      # EXPECT 1  encadeado, so 1

# ---------------- cifras: devem ser achadas
AES.new(key, AES.MODE_ECB)                         # EXPECT 1
AES.new(key, mode=AES.MODE_ECB)                    # EXPECT 1
A2.new(key, A2.MODE_ECB)                           # EXPECT 1  Cryptodome com alias
AES.new(key, 1)                                    # EXPECT 1  MODE_ECB == 1
mode_ecb = AES.MODE_ECB
AES.new(key, mode_ecb)                             # EXPECT 1  modo via variavel
AES.new(key)                                       # EXPECT 1  sem modo (legado = ECB)
DES.new(key, DES.MODE_CBC, iv)                     # EXPECT 1
DES3.new(key, DES3.MODE_CBC, iv)                   # EXPECT 1
ARC4.new(key)                                      # EXPECT 1
Crypto.Cipher.DES.new(key, 2)                      # EXPECT 1  caminho completo
Cipher(algorithms.TripleDES(k), modes.ECB())       # EXPECT 2  3DES + ECB
cipher = AES.new(                                  # EXPECT 1  chamada multilinha
    key,
    AES.MODE_ECB,
)

def dentro_de_funcao():
    import hashlib as inner
    return inner.md5(b"x")                         # EXPECT 1  import local

# ---------------- NAO devem ser achados
sha256(b"a")                                       # OK
hashlib.sha256(b"a")                               # OK
hashlib.new("sha256")                              # OK
hashlib.new(algo_var)                              # OK
hmac.new(k, m, hashlib.sha256)                     # OK
hmac.new(k, m, "sha256")                           # OK
AES.new(key, AES.MODE_GCM, nonce=n)                # OK
AES.new(key, AES.MODE_CBC, iv)                     # OK
AES.new(key, mode_desconhecido)                    # OK  nao resolvivel estaticamente
AES.new(*args)                                     # OK  dinamico
AES.new(**kwargs)                                  # OK  dinamico
DESCRIBE_x(1)                                      # OK  nome contem DES
my_DES_helper(2)                                   # OK
AESTHETIC.new(3)                                   # OK
foo().md5(b"a")                                    # OK  raiz nao resolvivel
helpers.md5(b"a")                                  # OK  import relativo
md5 = 3                                            # OK  atribuicao, nao uso
modes.CBC(iv)                                      # OK
algorithms.AES(k)                                  # OK
