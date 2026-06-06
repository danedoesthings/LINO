LUA_KEYWORDS: set[str] = {
    'function', 'local', 'end', 'return', 'if', 'then', 'else', 'elseif',
    'for', 'while', 'do', 'repeat', 'until', 'not', 'and', 'or',
    'nil', 'true', 'false', 'in', 'break', 'print', 'require',
    'pcall', 'xpcall', 'loadstring', 'load', 'pairs', 'ipairs',
    'setmetatable', 'getmetatable', 'rawset', 'rawget', 'tostring', 'tonumber',
    'table', 'string', 'math', 'coroutine', 'debug', 'io', 'os',
    'unpack', 'select', 'type', 'assert', 'error', 'next', 'rawequal',
}

PROTECTED_NAMES: set[str] = LUA_KEYWORDS | {
    'self', '_G', '_ENV', 'getfenv', 'setfenv', 'newproxy',
    'bit', 'bit32', 'game', 'workspace', 'Instance', 'task', 'typeof',
}

VM_SINGLE_LETTERS: dict[str, str] = {
    'R': 'EncStr', 'E': 'GetStr', 'l': 'vmState', 'Q': 'vmStack',
    'I': 'instrTbl', 'w': 'allocSlot', 'M': 'packArgs', 'Y': 'callEnvA',
    'r': 'callEnvB', 'N': 'alphaMap', 'h': 'charFn', 'J': 'funcWrap',
    'S': 'shuffleTbl', 'T': 'tokenMap', 'O': 'cleanRef',
}

SEMANTIC_RENAMES: list[tuple[str, str]] = [
    (r'\bloadstring\b', 'dynLoader'), (r'\bload\b(?!\w)', 'dynLoader'),
    (r'\bpcall\b', 'safecall'), (r'\bxpcall\b', 'safecallEx'),
    (r'\bsetmetatable\b', 'setMeta'), (r'\bgetmetatable\b', 'getMeta'),
    (r'\brawset\b', 'rawSet'), (r'\brawget\b', 'rawGet'),
    (r'\bEncryptedStrings\b', 'strTable'), (r'\bGetString\b', 'strGet'),
    (r'\bVirtualStack\b', 'vmStack'), (r'\bInstructionTable\b', 'instrTbl'),
    (r'\bAllocSlot\b', 'allocSlot'), (r'\bPackArgs\b', 'packArgs'),
    (r'\bCallEnv\b', 'callEnv'), (r'\bAlphabetMap\b', 'alphaMap'),
    (r'\bcharFunc\b', 'charFn'), (r'\bFuncWrap\b', 'funcWrap'),
    (r'\bShuffleTable\b', 'shuffleTbl'), (r'\bTokenMap\b', 'tokenMap'),
    (r'\bCleanupRef\b', 'cleanRef'),
]

def is_probably_text(data) -> bool:
    if not data:
        return False
    raw = data.encode('latin-1', errors='ignore') if isinstance(data, str) else bytes(data)
    if len(raw) < 6:
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(raw) >= 0.60

def is_readable_identifier(s: str) -> bool:
    if not s or len(s) > 64:
        return False
    if re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', s):
        return True
    return s in LUA_KEYWORDS

def escape_lua_string(s: str) -> str:
    import json
    return json.dumps(s)

def decode_numeric_escapes(s: str) -> str:
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)
