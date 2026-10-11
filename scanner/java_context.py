"""Resolve explicit JCA receiver configuration within the same lexical block.

No cross-method key propagation, alias analysis or runtime inference is done.
"""


def attach_java_context(visitor):
    tokens = visitor.tokens
    scopes = [{}]
    constants = {}
    byte_lengths = {}
    for name, expressions in visitor.const_exprs.items():
        if len(expressions) != 1:
            continue
        expression = expressions[0]
        values = [t.value for t in expression]
        if len(expression) == 8 and expression[0].kind == "str" and values[1:] == [".", "getBytes", "(", "StandardCharsets", ".", "UTF_8", ")"]:
            byte_lengths[name] = len(expression[0].value.encode("utf-8")) * 8
    for i, token in enumerate(tokens):
        if token.value != "=" or i < 1:
            continue
        start = i - 1
        while start > 0 and tokens[start - 1].value not in {";", "{", "}"}:
            start -= 1
        if "final" not in [t.value for t in tokens[start:i]]:
            continue
        if i + 2 < len(tokens) and tokens[i + 1].value.isdigit() and tokens[i + 2].value == ";":
            name = tokens[i - 1].value
            value = int(tokens[i + 1].value)
            constants[name] = value if name not in constants else None

    for i, token in enumerate(tokens):
        if token.value == "{":
            scopes.append({})
        elif token.value == "}":
            if len(scopes) > 1:
                scopes.pop()
        elif token.kind == "id" and i + 1 < len(tokens) and tokens[i + 1].value == "(":
            parts, start, resolvable = visitor._chain_before(i)
            args, end = visitor._args(i + 1)
            if not resolvable:
                continue
            if token.value == "SecretKeySpec" and start >= 3 and tokens[start - 1].value == "new" and tokens[start - 2].value == "=":
                matches = [f for f in visitor.findings if f.line == tokens[start - 1].line and f.params.get("function") == "keygen"]
                if len(matches) == 1:
                    finding = matches[0]
                    finding.params["function"] = "unknown"
                    if args and len(args[0]) == 1 and args[0][0].value in byte_lengths:
                        finding.params["key_size"] = str(byte_lengths[args[0][0].value])
                    scopes[-1][tokens[start - 3].value] = finding
            elif token.value == "getInstance" and parts and parts[-1] in {"KeyGenerator", "KeyPairGenerator", "Cipher", "Signature"}:
                if start >= 2 and tokens[start - 1].value == "=":
                    receiver = tokens[start - 2].value
                    operation = {"KeyGenerator": "keygen", "KeyPairGenerator": "keygen", "Cipher": "unknown", "Signature": "sign"}[parts[-1]]
                    matches = [f for f in visitor.findings if f.line == tokens[start].line and f.params.get("function") == operation]
                    # Multiple same-line factories cannot be linked by line alone.
                    if len(matches) == 1:
                        scopes[-1][receiver] = matches[0]
            elif len(parts) == 1 and parts[0] in scopes[-1]:
                finding = scopes[-1][parts[0]]
                if token.value in {"initSign", "initVerify"}:
                    finding.params["function"] = "sign" if token.value == "initSign" else "verify"
                elif token.value in {"initialize", "init"} and finding.params.get("function") == "keygen":
                    value = None
                    if args and len(args[0]) == 1:
                        raw = args[0][0].value
                        value = int(raw) if raw.isdigit() else constants.get(raw)
                    if value and value > 0:
                        finding.params["key_size"] = str(value)
                        finding.params["note"] = f"Explicit receiver configuration at line {token.line}"
                    else:
                        finding.params.pop("key_size", None)
                elif token.value == "init" and args and len(args[0]) == 3:
                    values = [t.value for t in args[0]]
                    if values[0] == "Cipher" and values[1] == "." and values[2] in {"ENCRYPT_MODE", "DECRYPT_MODE"}:
                        finding.params["function"] = "encrypt" if values[2] == "ENCRYPT_MODE" else "decrypt"
                        if len(args) > 1 and len(args[1]) == 1:
                            key = scopes[-1].get(args[1][0].value)
                            if key and key.params.get("key_size"):
                                finding.params["key_size"] = key.params["key_size"]
