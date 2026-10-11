import ast
import json
import re
import sys
import tokenize
from dataclasses import asdict, dataclass
from pathlib import Path


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

#---------------------------------------------- classe de imports
    def visit_module(self, node: ast.Module):
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
        self._call_funcs.add(id(node.func))
        candidates = self._candidates(node.func)
 
        self._check_weak_hash_call(node, candidates)
        self._check_hash_name_argument(node, candidates)
        self._check_cipher(node, candidates)
 
        self.generic_visit(node)

# Verifica funções de hash diretas (ex: md5(), sha1())
    def _check_weak_hash_call(self, node: ast.Call, candidates: list[str]):
        label = self._match(candidates, WEAK_HASHES)
        if not label:
            return
        params = {"note": "Obsoleted by security standards"}
        for kw in node.keywords:
            if kw.arg == "usedforsecurity" and ast.unparse(kw.value) == "False":
                params["usedforsecurity"] = "False"
                params["note"] += " (usedforsecurity=False: possible non-security use, review manually)"
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
                    self.add_finding(
                        node = node,
                        usage = "Weak Hash Algorithm",
                        algorithm = WEAK_HASH_NAMES[key],
                        params = {
                            "note": "Obsoleted by security standards",
                            "hash_name": expr.value,
                        }
                    )

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
        line_number = getattr(node, "lineno", 0)
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

def scan_file(file_path: str) -> list[cryptoFinding]:
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
        print(f"Erro ao ler {file_path}: {e}")
        return []
 
    # O ast só considera \n, \r\n e \r como quebra de linha; splitlines() também
    # quebra em \x0c, \x1c,  etc., o que desalinharia números de linha.
    source_lines = re.split(r"\r\n|\r|\n", source_code)
 
    try:
        tree = ast.parse(source_code, filename=file_path)
    except (SyntaxError, ValueError, RecursionError) as e:
        print(f"Erro de sintaxe em {file_path}: {e}")
        return []
 
    visitor = cryptoVisitor(filename=file_path, source_lines=source_lines)
    visitor.visit(tree)
 
    return visitor.findings

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
