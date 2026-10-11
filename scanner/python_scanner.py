from dataclasses import dataclass, asdict
from pathlib import Path
import json
import ast
import re
import sys
import tokenize

@dataclass
class cryptoFinding:
    filename: str
    line: int
    usage: str
    algorithm: str
    params: dict[str, str]
    evidence: str

WEAK_HASHES = {
    "hashlib.md5": "MD5",
    "hashlib.sha1": "SHA1",
    "MD2.new": "MD2",          # PyCryptodome
    "MD4.new": "MD4",
    "MD5.new": "MD5",
    "SHA1.new": "SHA1",
    "hashes.MD5": "MD5",       # cryptography
    "hashes.SHA1": "SHA1",
}

WEAK_HASH_NAMES = {"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha1": "SHA1"}
for _hash in ("sha224", "sha256", "sha384", "sha512"):
    WEAK_HASHES[f"hashlib.{_hash}"] = _hash.upper()
    WEAK_HASHES[f"hashes.SHA{_hash[3:]}"] = _hash.upper()
    WEAK_HASH_NAMES[_hash] = _hash.upper()

HASH_NAME_ARG_FUNCS = {
    "hashlib.new": (0, "name"),
    "hashlib.pbkdf2_hmac": (0, "hash_name"),
    "hmac.new": (2, "digestmod"),
    "hmac.digest": (2, "digest"),
}

WEAK_CIPHERS = {
    "DES.new": "DES",
    "DES3.new": "3DES",
    "ARC2.new": "RC2",
    "ARC4.new": "RC4",
    "Blowfish.new": "Blowfish",
    "algorithms.TripleDES": "3DES",
    "algorithms.ARC4": "RC4",
    "algorithms.Blowfish": "Blowfish",
    "algorithms.CAST5": "CAST5",
    "algorithms.IDEA": "IDEA",
}

WEAK_MODES = {"modes.ECB": "ECB"}

MODE_CHECKED_CIPHERS = {"AES.new": "AES"}

CIPHER_USAGE = "Weak Symmetric Algorithm / Mode"
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "env", "node_modules", "site-packages", ".tox"}
 
 
def _suffix_match(name: str, table: dict[str, str]) -> str | None:
    for suffix, label in table.items():
        if name == suffix or name.endswith("." + suffix):
            return label
    return None
 
 
def _normalize_module(name: str) -> str:
    # pycryptodome pode ser instalado como "Crypto" ou "Cryptodome"/"Cryptodomex"
    return re.sub(r"^Cryptodomex?(?=\.|$)", "Crypto", name)

class cryptoVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: list[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: list[cryptoFinding] = []
        self.alias : dict[str, str] = {}
        self.start_modules: list[str] = []
        self.mode_vars: dict[str, str] = {}
        self._call_funcs: set[int] = set()
        self._consumed_calls: set[int] = set()
        self._hash_context: dict[int, str] = {}

#---------------------------------------------- classe de imports
    def visit_Module(self, node: ast.Module):
        for n in ast.walk(node):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.alias[a.asname] = a.name
                    else:
                        root = a.name.split(".")[0]
                        self.alias[root] = a.name
            elif isinstance(n, ast.ImportFrom):
                if n.level or not n.module:
                    continue
                for a in n.names:
                    if a.name == "*":
                        self.start_modules.append(n.module)
                    else:
                        self.alias[a.asname or a.name] = f"{n.module}.{a.name}"
        self.generic_visit(node)

#----------------------------------------------- classe nome de funções
    def _get_func_name(self, node) -> str:
            if isinstance(node, ast.Name):
                return node.id
            elif isinstance(node, ast.Attribute):
                value = self._get_func_name(node.value)
                return f"{value}.{node.attr}" if value else node.attr
            return ""
#--------------------------------------------------- classe nome nó resolve alias e imports para achar o nome completo
    def _candidates(self, node) -> list[str]:
        raw = self._get_func_name(node)
        if not raw:
            return []
        head, _, rest = raw.partition(".")
        if head in self.alias:
            full_name = self.alias[head] + (f".{rest}" if rest else "")
            candidates = [full_name]
        else:
            candidates = [raw] + [f"{m}.{raw}" for m in self.start_modules]
        return [_normalize_module(c) for c in candidates]

#-------------------------------------------------------------------- classe compara os nomes ressolvidos com a tabela cifras fraca
    def _match(self, candidates: list[str], table: dict[str, str]) -> str | None:
        for c in candidates:
            label = _suffix_match(c, table)
            if label:
                return label
        return None

#------------------------------------------------------------------ variaveis de modo 
    def _track_assign(self, target, value):
        if isinstance(value, (ast.Name, ast.Attribute, ast.Constant)):
            for t in target:
                if isinstance(t, ast.Name):
                    self.mode_vars[t.id] = ast.unparse(value)

    def visit_Assign(self, node: ast.Assign):
        if node.value is not None:
            self._track_assign(node.targets, node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        saved = self.mode_vars.copy()
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.mode_vars.pop(arg.arg, None)
        for statement in node.body:
            self.visit(statement)
        self.mode_vars = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def _find_mode(self, node: ast.Call):
        """Retorna (texto, texto_resolvido, é_ECB) ou None se não há modo explícito."""
        expr = None
        for kw in node.keywords:
            if kw.arg == "mode":
                expr = kw.value
        if expr is None and len(node.args) >= 2:
            expr = node.args[1]
        if expr is None:
            for kw in node.keywords:
                if "MODE" in ast.unparse(kw.value):
                    expr = kw.value
            for arg in node.args:
                if "MODE" in ast.unparse(arg):
                    expr = arg
        if expr is None:
            return None

        text = ast.unparse(expr)
        resolved = text
        for _ in range(5):  # segue cadeias simples: a = AES.MODE_ECB; b = a
            if resolved in self.mode_vars:
                resolved = self.mode_vars[resolved]
            else:
                break
        # No PyCryptodome MODE_ECB == 1
        is_ecb = resolved.split(".")[-1] in ("MODE_ECB", "ECB") or resolved == "1"
        return text, resolved, is_ecb

#----------------------------------------------------------------------- classe de chamada
# orquestrador principal de chamadas de função
    def visit_Call(self, node: ast.Call):
        if id(node) in self._consumed_calls:
            self.generic_visit(node)
            return
        self._call_funcs.add(id(node.func))
        candidates = self._candidates(node.func)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"sign", "verify"}:
            if any(isinstance(arg, ast.Call) and any(c.endswith(("padding.PKCS1v15", "padding.PSS")) for c in self._candidates(arg.func)) for arg in node.args):
                for arg in node.args:
                    if isinstance(arg, ast.Call) and self._match(self._candidates(arg.func), WEAK_HASHES):
                        self._hash_context[id(arg)] = node.func.attr

        if self._check_construction(node, candidates):
            self.generic_visit(node)
            return
 
        self._check_weak_hash_call(node, candidates)
        self._check_hash_name_argument(node, candidates)
        if not self._check_inventory(node, candidates):
            self._check_cipher(node, candidates)
 
        self.generic_visit(node)

    def _literal(self, node):
        for _ in range(5):
            if isinstance(node, ast.Name) and node.id in self.mode_vars:
                try:
                    node = ast.parse(self.mode_vars[node.id], mode="eval").body
                except SyntaxError:
                    return None
            else:
                break
        return node.value if isinstance(node, ast.Constant) else None

    def _check_construction(self, node, candidates):
        """Keep explicit composite APIs together instead of unrelated children."""
        if _suffix_match_any(candidates, "PBKDF2HMAC"):
            values = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            digest_node = values.get("algorithm")
            digest = self._match(self._candidates(digest_node.func), WEAK_HASHES) if isinstance(digest_node, ast.Call) else None
            name = "PBKDF2-HMAC-" + digest if digest else "PBKDF2"
            params = {"function": "kdf"}
            details = {key: self._literal(values.get(key)) for key in ("length", "iterations")}
            params["note"] = "PBKDF2 source parameters (not password entropy): " + json.dumps(details)
            self.add_finding(node, "KDF", name, params)
            if isinstance(digest_node, ast.Call):
                self._consumed_calls.add(id(digest_node))
                self._call_funcs.add(id(digest_node.func))
            return True
        constructor = node
        operation = "unknown"
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            if node.func.attr in {"encrypt", "decrypt"}:
                constructor, operation = node.func.value, node.func.attr
        names = self._candidates(constructor.func)
        key = None
        mode = None
        children = []
        if _suffix_match_any(names, "AESGCM"):
            key = constructor.args[0] if constructor.args else next((kw.value for kw in constructor.keywords if kw.arg == "key"), None)
            mode = "GCM"
            if constructor is not node:
                children.append(constructor)
        elif _suffix_match_any(names, "Cipher") and constructor.args:
            cipher = constructor.args[0]
            if not isinstance(cipher, ast.Call) or not _suffix_match_any(self._candidates(cipher.func), "algorithms.AES"):
                return False
            key = cipher.args[0] if cipher.args else None
            mode_node = constructor.args[1] if len(constructor.args) > 1 else next((kw.value for kw in constructor.keywords if kw.arg == "mode"), None)
            if isinstance(mode_node, ast.Call):
                for candidate in self._candidates(mode_node.func):
                    for known in ("ECB", "CBC", "GCM", "CCM", "CTR", "CFB", "OFB"):
                        if candidate.endswith("modes." + known):
                            mode = known
                children.append(mode_node)
            children.append(cipher)
        else:
            return False
        params = {"function": operation}
        if mode:
            params["mode"] = mode
        literal = self._literal(key)
        if isinstance(literal, bytes) and literal:
            params["key_size"] = str(len(literal) * 8)
        self.add_finding(node, "Cipher construction", "AES", params)
        for child in children:
            self._consumed_calls.add(id(child))
            self._call_funcs.add(id(child.func))
        return True

# Verifica funções de hash diretas (ex: md5(), sha1())
    def _check_weak_hash_call(self, node: ast.Call, candidates: list[str]):
        label = self._match(candidates, WEAK_HASHES)
        if not label:
            return
        params = {"function": self._hash_context.get(id(node), "digest" if any(c.startswith("hashlib.") for c in candidates) else "unknown")}
        for kw in node.keywords:
            if kw.arg == "usedforsecurity" and ast.unparse(kw.value) == "False":
                params["usedforsecurity"] = "False"
                params["note"] = "usedforsecurity=False: possible non-security use, review manually"
        self.add_finding(
            node = node,
            usage = "Weak Hash Algorithm",
            algorithm = label,
            params = params
        )

 # Verifica hashes criados por string (ex: hashlib.new("md5"))
    def _check_hash_name_argument(self, node: ast.Call, candidates: list[str]):
        for suffix, (pos, kw_name) in HASH_NAME_ARG_FUNCS.items():
            if not _suffix_match_any(candidates, suffix):
                continue
            expr = None
            for kw in node.keywords:
                if kw.arg == kw_name:
                    expr = kw.value
            if expr is None and len(node.args) > pos:
                expr = node.args[pos]
            if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                key = expr.value.lower().replace("-", "").replace("_", "")
                if key in WEAK_HASH_NAMES:
                    digest = WEAK_HASH_NAMES[key]
                    operation = "digest"
                    if suffix.startswith("hmac."):
                        digest, operation = "HMAC-" + digest, "mac"
                    elif suffix == "hashlib.pbkdf2_hmac":
                        digest, operation = "PBKDF2-HMAC-" + digest, "kdf"
                    self.add_finding(
                        node = node,
                        usage = "Weak Hash Algorithm",
                        algorithm = digest,
                        params = {
                            "function": operation,
                            "hash_name": expr.value,
                        }
                    )
            elif expr is not None and suffix.startswith("hmac."):
                digest = self._match(self._candidates(expr), WEAK_HASHES)
                if digest:
                    self._call_funcs.add(id(expr))
                    self.add_finding(node, "MAC", "HMAC-" + digest, {"function": "mac"})

    def _check_inventory(self, node: ast.Call, candidates: list[str]) -> bool:
        """Inventory explicit key/cipher APIs in addition to weak primitives."""
        parameters = {}
        name = None
        operation = "unknown"
        if _suffix_match_any(candidates, "rsa.generate_private_key"):
            name, operation = "RSA", "keygen"
            value = next((kw.value for kw in node.keywords if kw.arg == "key_size"), None)
            if value is None and len(node.args) > 1:
                value = node.args[1]
            if isinstance(value, ast.Name) and value.id in self.mode_vars:
                try:
                    value = ast.parse(self.mode_vars[value.id], mode="eval").body
                except SyntaxError:
                    value = None
            if isinstance(value, ast.Constant) and type(value.value) is int and value.value > 0:
                parameters["key_size"] = str(value.value)
        elif any(_suffix_match_any(candidates, suffix) for suffix in ("Ed25519PrivateKey.generate", "ed25519.Ed25519PrivateKey.generate")):
            name, operation = "Ed25519", "keygen"
        elif _suffix_match_any(candidates, "AES.new") or _suffix_match_any(candidates, "algorithms.AES"):
            name = "AES"
            key = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "key"), None)
            if isinstance(key, ast.Name) and key.id in self.mode_vars:
                try:
                    key = ast.parse(self.mode_vars[key.id], mode="eval").body
                except SyntaxError:
                    key = None
            if isinstance(key, ast.Constant) and isinstance(key.value, bytes) and key.value:
                parameters["key_size"] = str(len(key.value) * 8)
            if _suffix_match_any(candidates, "AES.new"):
                mode = self._find_mode(node)
                if mode:
                    parameters["mode_resolved"] = mode[1]
        if name is None:
            return False
        parameters["function"] = operation
        self.add_finding(node, "Cryptographic primitive", name, parameters)
        return True

# Verifica cifras de criptografia e modos inseguros (ex: DES, AES em ECB)
    def _check_cipher(self, node: ast.Call, candidates: list[str]):
        label = self._match(candidates, WEAK_CIPHERS)
        if label:
            params = {}
            mode = self._find_mode(node)
            if mode:
                params["mode"] = mode[0]
            self.add_finding(
                node = node,
                usage = CIPHER_USAGE,
                algorithm = label,
                params = params
            )
            return
 
        label = self._match(candidates, WEAK_MODES)
        if label:
            self.add_finding(
                node = node,
                usage = CIPHER_USAGE,
                algorithm = label,
                params = {"mode": "ECB", "note": "ECB leaks plaintext patterns"}
            )
            return
 
        label = self._match(candidates, MODE_CHECKED_CIPHERS)
        if label:
            mode = self._find_mode(node)
            if mode:
                text, resolved, is_ecb = mode
                if is_ecb:
                    params = {"mode": text}
                    if resolved != text:
                        params["mode_resolved"] = resolved
                    self.add_finding(
                        node = node,
                        usage = CIPHER_USAGE,
                        algorithm = label,
                        params = params
                    )
            else:
                dynamic = any(isinstance(a, ast.Starred) for a in node.args) or \
                          any(kw.arg is None for kw in node.keywords)
                if not dynamic and len(node.args) <= 1:
                    self.add_finding(
                        node = node,
                        usage = CIPHER_USAGE,
                        algorithm = label,
                        params = {
                            "mode": "<not specified>",
                            "note": "No mode given; legacy PyCrypto defaults to ECB",
                        }
                    )

#------------------------------------------------------------------------- classe referências sem chamadas
# Pega referências que são atributos (ex: hashli8b.sha1)
    def visit_Attribute(self, node: ast.Attribute):
        self._check_hash_reference(node)
        self.generic_visit(node)

# Pega a referências que são nomes simples (ex: sha1)
    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self._check_hash_reference(node)

# Filtra e valida se essa referência é um hash fraco
    def _check_hash_reference(self, node):
        """Pega hmac.new(k, m, hashlib.sha1): a função é passada, não chamada."""
        if id(node) in self._call_funcs:
            return
        if isinstance(getattr(node, "ctx", None), (ast.Store, ast.Del)):
            return
        label = self._match(self._candidates(node), WEAK_HASHES)
        if label:
            self.add_finding(
                node = node,
                usage = "Weak Hash Algorithm (reference)",
                algorithm = label,
                params = {"note": "Obsoleted by security standards"}
            )
        
#---------------------------------------------------------------------------------------- registro
    def add_finding(self, node: ast.AST, usage: str, algorithm: str, params: dict[str, str]):
        # Record a resolved API namespace, not an assumed implementation/version.
        for item in ast.walk(node):
            target = item.func if isinstance(item, ast.Call) else item
            roots = [name.split(".")[0] for name in self._candidates(target)]
            root = next((root for root in roots if root in
                         {"hashlib", "hmac", "cryptography", "Crypto", "Cryptodome"}), None)
            if root:
                params.setdefault("library", root)
                break
        line_number = node.lineno
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


def _suffix_match_any(candidates: list[str], suffix: str) -> bool:
    return any(c == suffix or c.endswith("." + suffix) for c in candidates)

def scan_file(file_path: str, *, strict: bool = False) -> list[cryptoFinding]:
    path = Path(file_path)
    if not path.exists():
        print(f"Erro: O arquivo {file_path} não foi encontrado.")
        return []
    if not path.is_file():
        print(f"Erro: {file_path} não é um arquivo.")
        return []
 
    try:
        # tokenize.open respeita BOM e declaração de encoding (# -*- coding: ... -*-)
        with tokenize.open(path) as f:
            source_code = f.read()
    except (OSError, UnicodeDecodeError, SyntaxError) as e:
        if strict:
            raise ValueError(f"Cannot read Python source {file_path}: {e}") from e
        print(f"Erro ao ler {file_path}: {e}")
        return []
 
    # O ast só considera \n, \r\n e \r como quebra de linha; splitlines() também
    # quebra em \x0c, \x1c,  etc., o que desalinharia números de linha.
    source_lines = re.split(r"\r\n|\r|\n", source_code)
 
    try:
        tree = ast.parse(source_code, filename=file_path)
    except (SyntaxError, ValueError, RecursionError) as e:
        if strict:
            raise ValueError(f"Cannot parse Python source {file_path}: {e}") from e
        print(f"Erro de sintaxe em {file_path}: {e}")
        return []
 
    visitor = cryptoVisitor(filename=file_path, source_lines=source_lines)
    visitor.visit(tree)
 
    return visitor.findings

def scan_python_file(file_path: str | Path, base_dir: str | Path | None = None):
    """Shared scanner interface; risk assessment is performed downstream."""
    from scanner.source_adapter import adapt_source_finding
    return [adapt_source_finding(raw, "python", Path(base_dir) if base_dir else None)
            for raw in scan_file(str(file_path), strict=True)]


def collect_python_files(target: str) -> list[str]:
    path = Path(target)
    if path.is_dir():
        return sorted(
            str(p) for p in path.rglob("*.py")
            if not any(part in SKIP_DIRS for part in p.parts)
        )
    return [target]

if __name__ == "__main__":
    targets = sys.argv[1:] or ["artifact_manifest.py"]
    files = [f for t in targets for f in collect_python_files(t)]
 
    print(f"Iniciando varredura de {len(files)} arquivo(s): {', '.join(targets)} ...\n")
 
    results: list[cryptoFinding] = []
    for file in files:
        results.extend(scan_file(file))
 
    if results:
        print(f"Sucesso! Foram encontrados {len(results)} registro criptográfico(s) suspeito(s):\n")
        print(json.dumps([asdict(f) for f in results], indent=4, ensure_ascii=False))
 
    else:
        print("Nenhum registro criptográfico suspeito foi encontrado.")
