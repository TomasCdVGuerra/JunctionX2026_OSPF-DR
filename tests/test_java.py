import re
import sys
from collections import Counter
from pathlib import Path

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI))
from java_scanner import scan_file

falhou = False
for nome in ("SampleJdk.java", "SampleLibs.java"):
    amostra = AQUI / nome
    esperado = Counter()
    for i, linha in enumerate(amostra.read_text(encoding="utf-8").split("\n"), 1):
        m = re.search(r"// EXPECT (\d+)", linha)
        if m:
            esperado[i] = int(m.group(1))

    achado = Counter(f.line for f in scan_file(str(amostra)))
    faltando = {l: (esperado[l], achado.get(l, 0)) for l in esperado if achado.get(l, 0) != esperado[l]}
    sobrando = {l: c for l, c in achado.items() if l not in esperado}

    print(f"[{nome}] Esperados: {sum(esperado.values())} | Achados: {sum(achado.values())}")
    print("   Divergências (linha: esperado, achado):", faltando or "nenhuma")
    print("   Falsos positivos (linha: quantidade):  ", sobrando or "nenhum")
    if faltando or sobrando:
        falhou = True

if falhou:
    print("\nRESULTADO: FALHOU")
    sys.exit(1)
print("\nRESULTADO: OK")
