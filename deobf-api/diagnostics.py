import re, os, time, json
from errors import LinoError

try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

try:
    from pygments.lexers.scripting import LuaLexer
    HAS_PYGMENTS = True
except ImportError:
    HAS_PYGMENTS = False

BAD_PATTERNS = [
    (r'(\d+)\s+end', 'missing_newline_number_end'),
    (r'(\d+)\s+then', 'missing_newline_number_then'),
    (r'(\d+)\s+else', 'missing_newline_number_else'),
    (r'(\d+)\s+do', 'missing_newline_number_do'),
    (r'\.\.\s*\.\.', 'broken_concat'),
    (r',\s*,', 'duplicate_comma'),
    (r'function\s+end', 'empty_function'),
    (r'if\s+then\s+end', 'empty_if'),
    (r'end\s+local', 'missing_newline_end_local'),
    (r'return\s+function', 'return_function_missing_space'),
]

def validate_lua(code):
    if not HAS_LUAPARSER:
        return {"valid": False, "error": "luaparser not installed", "type": "ImportError"}
    try:
        lua_ast.parse(code)
        return {"valid": True}
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "type": type(e).__name__
        }

def parse_lua_error(err_text):
    text = str(err_text)
    match = re.search(r'line (\d+)', text)
    line = int(match.group(1)) if match else None
    col_match = re.search(r'col (\d+)', text)
    column = int(col_match.group(1)) if col_match else None
    return {
        "raw": text,
        "line": line,
        "column": column
    }

def extract_error_context(code, line, radius=3):
    if line is None:
        return None
    lines = code.splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    result = []
    for i in range(start, end):
        prefix = ">>" if i + 1 == line else "  "
        result.append(f"{prefix} {i+1}: {lines[i]}")
    return "\n".join(result)

def diagnostic_parse(code, stage="unknown"):
    result = validate_lua(code)
    if result["valid"]:
        return True
    info = parse_lua_error(result["error"])
    context = None
    if info["line"]:
        context = extract_error_context(code, info["line"])
    raise LinoError(
        stage=stage,
        message=result["error"],
        line=info["line"],
        column=info.get("column"),
        code_snippet=context
    )

def tokenize_lua(code):
    if not HAS_PYGMENTS:
        return []
    lexer = LuaLexer()
    return list(lexer.get_tokens(code))

def detect_bad_patterns(code):
    found = []
    for pattern, name in BAD_PATTERNS:
        for m in re.finditer(pattern, code):
            line = code[:m.start()].count('\n') + 1
            found.append({
                "pattern": name,
                "match": m.group(0),
                "line": line,
                "position": m.start()
            })
    return found

def auto_fix_lua(code):
    fixes = [
        (r'(\d+)\s+end', r'\1\nend'),
        (r'(\d+)\s+then', r'\1\nthen'),
        (r'(\d+)\s+else', r'\1\nelse'),
        (r'(\d+)\s+elseif', r'\1\nelseif'),
        (r'(\d+)\s+do', r'\1\ndo'),
        (r'end\s+local', 'end\nlocal'),
        (r'end\s+if', 'end\nif'),
        (r'end\s+for', 'end\nfor'),
        (r'end\s+while', 'end\nwhile'),
        (r',\s*,', ','),
        (r'\.\s+\.', '..'),
        (r'\.\.\s*\.\.', '..'),
        (r'function\s+end', 'function dummy() end'),
        (r'if\s+then\s+end', 'if true then end'),
        (r'=\s*function\s*\(', '= function('),
    ]
    for pattern, replacement in fixes:
        code = re.sub(pattern, replacement, code)
    return code

def confidence_score(code):
    score = 100
    penalties = {
        r'(\d+)\s+end': 50,
        r'\.\.\s*\.\.': 30,
        r',\s*,': 20,
        r'function\s+end': 40,
        r'if\s+then\s+end': 40,
        r'\\x[0-9a-fA-F]{2}': 10,
        r'[^\x20-\x7E\n\r\t]': 30,
    }
    for pattern, penalty in penalties.items():
        if re.search(pattern, code):
            score -= penalty
    if len(code) < 50:
        score -= 80
    words = set(re.findall(r'\b\w+\b', code[:10000]))
    lua_keywords = {'function', 'local', 'end', 'return', 'if', 'then', 'else', 'for', 'while', 'do', 'nil', 'true', 'false'}
    if len(words & lua_keywords) < 2:
        score -= 60
    return max(score, 0)

def save_crash_snapshot(transformer_name, before, after, error):
    os.makedirs("crashes", exist_ok=True)
    ts = int(time.time())
    with open(f"crashes/{ts}_{transformer_name}_before.lua", "w", encoding="utf-8") as f:
        f.write(before if before else "")
    with open(f"crashes/{ts}_{transformer_name}_after.lua", "w", encoding="utf-8") as f:
        f.write(after if after else "")
    with open(f"crashes/{ts}_{transformer_name}_error.txt", "w", encoding="utf-8") as f:
        f.write(str(error))

def log_structured_error(err):
    payload = err.to_dict() if isinstance(err, LinoError) else {
        "stage": "unknown",
        "message": str(err)
    }
    print(json.dumps(payload, indent=4))

def pipeline_validate_stage(code, stage_name):
    bad = detect_bad_patterns(code)
    if bad:
        details = "; ".join(f"{b['pattern']} at line {b['line']}" for b in bad[:3])
        raise LinoError(
            stage=stage_name,
            message=f"Bad patterns detected: {details}",
            line=bad[0]['line'] if bad else None,
            code_snippet=extract_error_context(code, bad[0]['line']) if bad else None,
            confidence=confidence_score(code)
        )
    if HAS_LUAPARSER:
        try:
            lua_ast.parse(code)
        except Exception as e:
            info = parse_lua_error(e)
            raise LinoError(
                stage=stage_name,
                message=str(e),
                line=info["line"],
                column=info.get("column"),
                code_snippet=extract_error_context(code, info["line"]) if info["line"] else None,
                confidence=confidence_score(code)
            )
    return True
