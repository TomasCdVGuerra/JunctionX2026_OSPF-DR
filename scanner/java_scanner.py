from dataclasses import dataclass, asdict
from pathlib import Path
import re
import json

@dataclass
class cryptoFinding:
    filename: str
    line: int
    usage: str
    algorithm: str
    params: dict[str, str]
    evidence: str

@dataclass
class Token:
    kind: str
    value: str
    line: int

# ---------------------------------- Tabela de Regras
HASH_USAGE = "Weak Hash Algorithm"
CIPHER_USAGE = "Weak Symmetric Algorithm / Mode"

# Nomes de hash fracos
WEAK_HASH_NAMES = {"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha": "SHA1", "sha1": "SHA1"}

# Cifras fracas (nomes em minúsculo)
WEAK_CIPHER_NAMES = {
     "des": "DES",
    "desede": "3DES",
    "tripledes": "3DES",
    "rc2": "RC2",
    "rc4": "RC4",
    "arcfour": "RC4",
    "blowfish": "Blowfish",
    "idea": "IDEA",
    "cast5": "CAST5",
}

# Cifras fortes cujo o MODO precisa ser verificado
CHECKED_CIPHER = re.compile(r"^aes(_(128|192|256))?$")

# (Classe, método) que recebem o NOME do algoritmo como string
STRING_ALGORITHM_SINKS = {
    ("MessageDigest", "getInstance"): ("digest", 0),
    ("DigestUtils", "getDigest"): ("digest", 0),
    ("Mac", "getInstance"): ("mac", 0),
    ("HmacUtils", "getInitializedMac"): ("mac", 0),
    ("Signature", "getInstance"): ("signature", 0),
    ("Cipher", "getInstance"): ("cipher", 0),
    ("KeyGenerator", "getInstance"): ("key", 0),
    ("SecretKeyFactory", "getInstance"): ("key", 0),
}

# Construtores de classe, que recebem o nome do algoritmo como string
CONSTRUCTOR_STRING_SINKS = {
    "SecretKeySpec": ("key", 1),
    "DigestUtils": ("digest", 0),
    "HmacUtils": ("mac", 0),
}

# Métodos auxiliadores que já embutem o hash fraco no nome
WEAK_HASH_HELPERS = {
    "DigestUtils": {
        "md2": "MD2", "md2Hex": "MD2",
        "md5": "MD5", "md5Hex": "MD5", "getMd5Digest": "MD5",
        "md5DigestAsHex": "MD5", "md5Digest": "MD5", "appendMd5DigestAsHex": "MD5",  # Spring
        "sha1": "SHA1", "sha1Hex": "SHA1", "getSha1Digest": "SHA1",
        "sha": "SHA1", "shaHex": "SHA1", "getShaDigest": "SHA1",
    },
    "Hashing": {"md5": "MD5", "sha1": "SHA1", "hmacMd5": "HmacMD5", "hmacSha1": "HmacSHA1"},
    "HmacUtils": {
        "hmacMd5": "HmacMD5", "hmacMd5Hex": "HmacMD5",
        "hmacSha1": "HmacSHA1", "hmacSha1Hex": "HmacSHA1",
    },
}

# Construtores de primitivas fracas
CONSTRUCTOR_RULES = {
    "MD2Digest": (HASH_USAGE, "MD2"),
    "MD4Digest": (HASH_USAGE, "MD4"),
    "MD5Digest": (HASH_USAGE, "MD5"),
    "SHA1Digest": (HASH_USAGE, "SHA1"),
    "DESEngine": (CIPHER_USAGE, "DES"),
    "DESedeEngine": (CIPHER_USAGE, "3DES"),
    "RC2Engine": (CIPHER_USAGE, "RC2"),
    "RC4Engine": (CIPHER_USAGE, "RC4"),
    "BlowfishEngine": (CIPHER_USAGE, "Blowfish"),
    "DESKeySpec": (CIPHER_USAGE, "DES"),
    "DESedeKeySpec": (CIPHER_USAGE, "3DES"),
}

# Constantes que nomeiam algoritmos fracos
REFERENCE_RULES = {
    ("HmacAlgorithms", "HMAC_MD5"): "HmacMD5",
    ("HmacAlgorithms", "HMAC_SHA_1"): "HmacSHA1",
    ("MessageDigestAlgorithms", "MD2"): "MD2",
    ("MessageDigestAlgorithms", "MD5"): "MD5",
    ("MessageDigestAlgorithms", "SHA_1"): "SHA1",
}

EXPECTED_PACKAGES = {
    "MessageDigest": ("java.security",),
    "Signature": ("java.security",),
    "Cipher": ("javax.crypto",),
    "Mac": ("javax.crypto",),
    "KeyGenerator": ("javax.crypto",),
    "SecretKeyFactory": ("javax.crypto",),
    "SecretKeySpec": ("javax.crypto.spec",),
    "DESKeySpec": ("javax.crypto.spec",),
    "DESedeKeySpec": ("javax.crypto.spec",),
    "DigestUtils": ("org.apache.commons.codec.digest", "org.springframework.util"),
    "HmacUtils": ("org.apache.commons.codec.digest",),
    "HmacAlgorithms": ("org.apache.commons.codec.digest",),
    "MessageDigestAlgorithms": ("org.apache.commons.codec.digest",),
    "Hashing": ("com.google.common.hash",),
    **{name: ("org.bouncycastle",) for name in CONSTRUCTOR_RULES if name.endswith(("Digest", "Engine")) and "KeySpec" not in name},
}
 
SKIP_DIRS = {".git", "target", "build", "out", "node_modules", ".gradle", ".idea", ".mvn", "bin"}
 
TWO_CHAR_OPS = {"==", "!=", "<=", ">=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "->", "::", "&&", "||", "++", "--"}
STRING_METHODS_TRANSPARENT = {"toUpperCase", "toLowerCase", "trim", "intern", "strip"}

#------------------------------ Tonkenizador de Java ----------------------------------------------------------------------------------
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "s": " ", "0": "\0",
            '"': '"', "'": "'", "\\": "\\"}

def _unescape(text: str) -> str:
    def repl(m: re.Match) -> str:
        if m.group(1):
            return chr(int(m.group(1), 16))
        return _ESCAPES.get(m.group(2), m.group(2))
    return re.sub(r"\\u+([0-9a-fA-F]{4})|\\(.)", repl, text, flags=re.S)


def tokenize(src: str) -> tuple[list[Token], list[str]]:
    """Converte o código em tokens. Comentários são descartados e o conteúdo de
    strings nunca é interpretado como código. Retorna (tokens, avisos)."""
    tokens: list[Token] = []
    warnings: list[str] = []
    i, n, line = 0, len(src), 1
 
    while i < n:
        c = src[i]
 
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\f\r":
            i += 1
 
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j
 
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j == -1:
                warnings.append(f"comentário de bloco não fechado (linha {line})")
                j = n - 2
            line += src.count("\n", i, j + 2)
            i = j + 2
 
        elif src.startswith('"""', i):  # text block
            k = i + 3
            while k < n and not src.startswith('"""', k):
                k += 2 if src[k] == "\\" else 1
            if k >= n:
                warnings.append(f"text block não fechado (linha {line})")
                k = n
            tokens.append(Token("str", _unescape(src[i + 3:k]).strip(), line))
            line += src.count("\n", i, k)
            i = k + 3
 
        elif c in "\"'":
            kind = "str" if c == '"' else "char"
            k = i + 1
            while k < n and src[k] != c and src[k] != "\n":
                k += 2 if src[k] == "\\" else 1
            if k >= n or src[k] == "\n":
                warnings.append(f"literal não fechado (linha {line})")
                tokens.append(Token(kind, _unescape(src[i + 1:k]), line))
                i = k
            else:
                tokens.append(Token(kind, _unescape(src[i + 1:k]), line))
                i = k + 1
 
        elif c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            tokens.append(Token("id", src[i:j], line))
            i = j
 
        elif c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            tokens.append(Token("num", src[i:j], line))
            i = j
 
        else:
            two = src[i:i + 2]
            if two in TWO_CHAR_OPS:
                tokens.append(Token("op", two, line))
                i += 2
            else:
                tokens.append(Token("op", c, line))
                i += 1
 
    return tokens, warnings

# Classificação de nomes de algoritmos
def _weak_hash_label(name: str) -> str | None:
    return WEAK_HASH_NAMES.get(name.lower().replace("-", ""))

def _is_weak_pbe(low: str) -> bool:
    return low.startswith("pbewith") and any(x in low for x in ("md5", "des", "rc2", "rc4"))

def classify_algorithm(kind: str, value: str) -> tuple[str, str, dict[str, str]] | None:
    """Recebe o tipo do ponto de uso e a string do algoritmo. Retorna
    (usage, algorithm, params) se for fraco, ou None."""
    s = value.strip()
    low = s.lower()
 
    if kind == "digest":
        label = _weak_hash_label(s)
        if label:
            return HASH_USAGE, label, {"note": "Obsoleted by security standards", "hash_name": s}
 
    elif kind == "mac":
        if low.startswith("hmac"):
            label = _weak_hash_label(low[4:])
            if label:
                return HASH_USAGE, "Hmac" + label, {"note": "Obsoleted by security standards", "hash_name": s}
 
    elif kind == "signature":
        m = re.match(r"^(md2|md5|sha1|sha-1)with", low)
        if m:
            return HASH_USAGE, s, {
                "note": "Obsoleted by security standards",
                "hash": _weak_hash_label(m.group(1)) or m.group(1),
            }
 
    elif kind in ("cipher", "key"):
        parts = [p.strip() for p in s.split("/")]
        alg = parts[0].lower()
        mode = parts[1] if len(parts) > 1 else None
 
        if _is_weak_pbe(alg):
            return CIPHER_USAGE, s, {"note": "Password-based encryption built on weak primitives"}
 
        if alg in WEAK_CIPHER_NAMES:
            params = {"transformation": s} if kind == "cipher" else {"algorithm_name": s}
            if mode:
                params["mode"] = mode
            return CIPHER_USAGE, WEAK_CIPHER_NAMES[alg], params
 
        if kind == "key" and alg.startswith("pbkdf2withhmac"):
            label = _weak_hash_label(alg[len("pbkdf2withhmac"):])
            if label:
                return HASH_USAGE, "Hmac" + label, {"note": "Obsoleted by security standards", "hash_name": s}
 
        if kind == "cipher" and CHECKED_CIPHER.match(alg):
            if mode is None:
                return CIPHER_USAGE, "AES", {
                    "transformation": s,
                    "mode": "<default: ECB>",
                    "note": "Java uses ECB when only the algorithm is given (e.g. 'AES' = 'AES/ECB/PKCS5Padding')",
                }
            if mode.upper() == "ECB":
                return CIPHER_USAGE, "AES", {"transformation": s, "mode": mode}
 
    return None

# Classe Visitor
class cryptoVisitor:
    def __init__(self, filename: str, source_lines: list[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: list[cryptoFinding] = []
        self.tokens: list[Token] = []
        self.depth: list[int] = []                       # profundidade de parênteses antes de cada token
        self.imports: dict[str, str] = {}                # nome simples -> nome qualificado
        self.static_imports: dict[str, str] = {}         # método -> classe qualificada
        self.static_wildcards: list[str] = []            # classes com "import static X.*"
        self.const_exprs: dict[str, list[list[Token]]] = {}
 
    def visit(self, tokens: list[Token]):
        self.tokens = tokens
        self._compute_depth()
        self._collect_imports()
        self._collect_constants()
        self._scan()

#--------------------------------------------------- Função preparação
    def _compute_depth(self):
        d = 0
        for t in self.tokens:
            self.depth.append(d)
            if t.kind == "op":
                if t.value == "(":
                    d += 1
                elif t.value == ")" and d > 0:
                    d -= 1

    def _is_op(self, i: int, value: str) -> bool:
        return 0 <= i < len(self.tokens) and self.tokens[i].kind == "op" and self.tokens[i].value == value

    def _is_id(self, i: int, value: str | None = None) -> bool:
        if not (0 <= i < len(self.tokens)) or self.tokens[i].kind != "id":
            return False
        return value is None or self.tokens[i].value == value

    def _collect_imports(self):
        toks = self.tokens
        for i, t in enumerate(toks):
            if not (t.kind == "id" and t.value == "import"):
                continue
            j = i + 1
            is_static = self._is_id(j, "static")
            if is_static:
                j += 1
            parts: list[str] = []
            wildcard = False
            while j < len(toks) and not self._is_op(j, ";"):
                if toks[j].kind == "id":
                    parts.append(toks[j].value)
                elif self._is_op(j, "*"):
                    wildcard = True
                j += 1
            if not parts:
                continue
            if is_static:
                if wildcard:
                    self.static_wildcards.append(".".join(parts))
                elif len(parts) >= 2:
                    self.static_imports[parts[-1]] = ".".join(parts[:-1])
            elif not wildcard:
                self.imports[parts[-1]] = ".".join(parts)

    def _collect_constants(self):
        """Registra 'NOME = <expressão>' para resolver strings guardadas em campos/variáveis."""
        toks = self.tokens
        for i, t in enumerate(toks):
            if not (t.kind == "op" and t.value == "=" and self.depth[i] == 0):
                continue
            if i == 0 or toks[i - 1].kind != "id":
                continue
            rhs: list[Token] = []
            j = i + 1
            while j < len(toks):
                tj = toks[j]
                if tj.kind == "op" and tj.value in (";", ",", "}") :
                    break
                if tj.kind == "op" and tj.value == ")" and self.depth[j] == 0:
                    break
                rhs.append(tj)
                j += 1
            if rhs:
                self.const_exprs.setdefault(toks[i - 1].value, []).append(rhs)

#------------------------------------------- Classe avaliação de string simples ----------------------------
    def _eval_strings(self, tokens: list[Token], depth: int = 0) -> list[str] | None:
        toks = list(tokens)
        # remove sufixos transparentes: .toUpperCase() / .toLowerCase() / .trim()
        while (len(toks) >= 4 and toks[-1].value == ")" and toks[-2].value == "("
               and toks[-3].kind == "id" and toks[-3].value in STRING_METHODS_TRANSPARENT
               and toks[-4].value == "."):
            toks = toks[:-4]
        toks = [t for t in toks if not (t.kind == "op" and t.value in ("(", ")"))]
        if not toks:
            return None
 
        terms: list[list[Token]] = [[]]
        for t in toks:
            if t.kind == "op" and t.value == "+":
                terms.append([])
            else:
                terms[-1].append(t)
 
        results = [""]
        for term in terms:
            values = self._eval_term(term, depth)
            if values is None:
                return None
            results = [a + b for a in results for b in values][:16]
        return results

    def _eval_term(self, term: list[Token], depth: int) -> list[str] | None:
        if len(term) == 1 and term[0].kind == "str":
            return [term[0].value]
        # identificador simples ou qualificado (NOME, this.NOME, Classe.NOME)
        if term and len(term) % 2 == 1 and all(
            (t.kind == "id") if k % 2 == 0 else (t.kind == "op" and t.value == ".")
            for k, t in enumerate(term)
        ):
            name = term[-1].value
            if depth > 5 or name not in self.const_exprs:
                return None
            values: list[str] = []
            for expr in self.const_exprs[name]:
                r = self._eval_strings(expr, depth + 1)
                if r:
                    values.extend(v for v in r if v not in values)
            return values or None
        return None

#-------------------------- Resolução de Nomes ---------------------------------------------
    def _pkg_ok(self, simple: str, fqn: str | None) -> bool:
        pkgs = EXPECTED_PACKAGES.get(simple)
        if pkgs is None or fqn is None:
            return True
        return any(fqn.startswith(p + ".") for p in pkgs)
 
    def _class_ok(self, parts: list[str]) -> bool:
        """parts = [..., NomeDaClasse]. Valida pelo import explícito ou pelo nome qualificado."""
        simple = parts[-1]
        if len(parts) > 1 and parts[0][:1].islower():
            return self._pkg_ok(simple, ".".join(parts))          # uso totalmente qualificado
        return self._pkg_ok(simple, self.imports.get(simple))     # import explícito (se houver)
 
    def _chain_before(self, i: int) -> tuple[list[str], int, bool]:
        """Qualificadores antes do identificador em i: (partes, índice_do_início, resolvível)."""
        if not self._is_op(i - 1, "."):
            return [], i, True
        parts: list[str] = []
        j = i - 2
        start = i
        while True:
            if not self._is_id(j):
                return [], i, False   # raiz não resolvível: foo().x, "txt".x, arr[0].x ...
            parts.insert(0, self.tokens[j].value)
            start = j
            if self._is_op(j - 1, "."):
                j -= 2
            else:
                break
        return parts, start, True
 
    def _args(self, open_idx: int) -> tuple[list[list[Token]], int]:
        """Argumentos da chamada cujo '(' está em open_idx. Retorna (args, índice_do_')')."""
        toks = self.tokens
        args: list[list[Token]] = []
        cur: list[Token] = []
        nest = 0
        j = open_idx + 1
        while j < len(toks):
            t = toks[j]
            if t.kind == "op":
                if t.value in "([{":
                    nest += 1
                elif t.value in ")]}":
                    if nest == 0:
                        break
                    nest -= 1
                elif t.value == "," and nest == 0:
                    args.append(cur)
                    cur = []
                    j += 1
                    continue
            cur.append(t)
            j += 1
        if cur or args:
            args.append(cur)
        return args, j

#------------------------ Varredura dos arquivos ------------------------------------------
    def _scan(self):
        toks = self.tokens
        for i, t in enumerate(toks):
            if t.kind != "id":
                continue
 
            if self._is_op(i + 1, "("):
                self._handle_call(i)
            elif self._is_op(i + 1, "::") and self._is_id(i + 2):
                self._handle_method_reference(i)
            elif self._is_op(i + 1, ".") and self._is_id(i + 2) and not self._is_op(i + 3, "("):
                self._handle_constant_reference(i)

    def _handle_call(self, i: int):
        toks = self.tokens
        name = toks[i].value
        parts, start, resolvable = self._chain_before(i)
        if not resolvable:
            return
        is_new = self._is_id(start - 1, "new")
        args, _ = self._args(i + 1)
        line = toks[start - 1].line if is_new else toks[start].line
 
        if is_new:
            qualified = parts + [name]
            if not self._class_ok(qualified):
                return
            if name in CONSTRUCTOR_RULES:
                usage, label = CONSTRUCTOR_RULES[name]
                self.add_finding(line, usage, label, {"note": "Obsoleted by security standards"})
            if name in CONSTRUCTOR_STRING_SINKS:
                kind, pos = CONSTRUCTOR_STRING_SINKS[name]
                self._check_string_argument(line, kind, args, pos)
            return
 
        if parts:
            cls = parts[-1]
            if not self._class_ok(parts):
                return
            self._apply_method_rules(line, cls, name, args)
            return
 
        # Chamada sem qualificador: só interessa se veio de import static
        owners: list[str] = []
        if name in self.static_imports:
            owners.append(self.static_imports[name])
        owners.extend(self.static_wildcards)
        for owner in owners:
            cls = owner.split(".")[-1]
            if self._pkg_ok(cls, owner) and self._apply_method_rules(line, cls, name, args):
                return
 
    def _apply_method_rules(self, line: int, cls: str, method: str, args: list[list[Token]]) -> bool:
        hit = False
        helper = WEAK_HASH_HELPERS.get(cls, {}).get(method)
        if helper:
            self.add_finding(line, HASH_USAGE, helper, {"note": "Obsoleted by security standards"})
            hit = True
        sink = STRING_ALGORITHM_SINKS.get((cls, method))
        if sink:
            kind, pos = sink
            self._check_string_argument(line, kind, args, pos)
            hit = True
        return hit
 
    def _check_string_argument(self, line: int, kind: str, args: list[list[Token]], pos: int):
        if len(args) <= pos:
            return
        expr = args[pos]
        values = self._eval_strings(expr)
        if not values:
            return
        is_literal = len(expr) == 1 and expr[0].kind == "str"
        for value in values:
            result = classify_algorithm(kind, value)
            if not result:
                continue
            usage, algorithm, params = result
            if not is_literal:
                params["resolved_from"] = " ".join(t.value for t in expr)
                if len(values) > 1:
                    params["ambiguous"] = "true"
            self.add_finding(line, usage, algorithm, params)
 
    def _handle_method_reference(self, i: int):
        """DigestUtils::md5Hex, MD5Digest::new ..."""
        toks = self.tokens
        parts, start, resolvable = self._chain_before(i)
        if not resolvable:
            return
        qualified = parts + [toks[i].value]
        cls, method = qualified[-1], toks[i + 2].value
        if not self._class_ok(qualified):
            return
        line = toks[start].line
        helper = WEAK_HASH_HELPERS.get(cls, {}).get(method)
        if helper:
            self.add_finding(line, HASH_USAGE + " (reference)", helper,
                             {"note": "Obsoleted by security standards"})
        elif method == "new" and cls in CONSTRUCTOR_RULES:
            usage, label = CONSTRUCTOR_RULES[cls]
            self.add_finding(line, usage + " (reference)", label,
                             {"note": "Obsoleted by security standards"})
 
    def _handle_constant_reference(self, i: int):
        """HmacAlgorithms.HMAC_MD5, MessageDigestAlgorithms.SHA_1 ..."""
        toks = self.tokens
        label = REFERENCE_RULES.get((toks[i].value, toks[i + 2].value))
        if not label:
            return
        parts, start, resolvable = self._chain_before(i)
        if not resolvable:
            return
        if not self._class_ok(parts + [toks[i].value]):
            return
        self.add_finding(toks[start].line, HASH_USAGE + " (reference)", label,
                         {"note": "Obsoleted by security standards"})

#--------------------------- Encontrar e formatar a vunerabilidade --------------------------------------
    def add_finding(self, line_number: int, usage: str, algorithm: str, params: dict[str, str]):
        if 1 <= line_number <= len(self.source_lines):
            evidence_line = self.source_lines[line_number - 1].strip()
        else:
            evidence_line = ""
 
        finding = cryptoFinding(
            filename = self.filename,
            line = line_number,
            usage = usage,
            algorithm = algorithm,
            params = params,
            evidence = evidence_line,
        )
 
        self.findings.append(finding)
     
#------------------------- Leitura de Arquivos -------------------------------------
def scan_file(file_path: str) -> list[cryptoFinding]:
    path = Path(file_path)
    if not path.exists():
        print(f"Erro: O arquivo {file_path} não foi encontrado.")
        return []
    if not path.is_file():
        print(f"Erro: {file_path} não é um arquivo.")
        return []
 
    try:
        raw = path.read_bytes()
    except OSError as e:
        print(f"Erro ao ler {file_path}: {e}")
        return []
 
    try:
        source_code = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Muito código Java legado está em ISO-8859-1; os identificadores de API são ASCII
        source_code = raw.decode("latin-1")
        print(f"Aviso: {file_path} não é UTF-8 válido; lido como ISO-8859-1.")
 
    if "\x00" in source_code:
        print(f"Erro: {file_path} parece ser binário (contém byte nulo).")
        return []
 
    # Java trata \n, \r\n e \r como quebra de linha
    source_code = source_code.replace("\r\n", "\n").replace("\r", "\n")
    source_lines = source_code.split("\n")
 
    tokens, warnings = tokenize(source_code)
    for w in warnings:
        print(f"Aviso em {file_path}: {w}. O resultado pode estar incompleto.")
 
    visitor = cryptoVisitor(filename=file_path, source_lines=source_lines)
    visitor.visit(tokens)
 
    return visitor.findings
 
 
def collect_java_files(target: str) -> list[str]:
    path = Path(target)
    if path.is_dir():
        return sorted(
            str(p) for p in path.rglob("*.java")
            if not any(part in SKIP_DIRS for part in p.parts)
        )
    return [target]
 
 
if __name__ == "__main__":
    targets = sys.argv[1:] or ["."]
    files = [f for t in targets for f in collect_java_files(t)]
 
    print(f"Iniciando varredura de {len(files)} arquivo(s): {', '.join(targets)} ...\n")
 
    results: list[cryptoFinding] = []
    for file in files:
        results.extend(scan_file(file))
 
    if results:
        print(f"Sucesso! Foram encontrados {len(results)} registro criptográfico(s) suspeito(s):\n")
        print(json.dumps([asdict(f) for f in results], indent=4, ensure_ascii=False))
 
    else:
        print("Nenhum registro criptográfico suspeito foi encontrado.")
 