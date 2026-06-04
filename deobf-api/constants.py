import math, re, json, base64
from collections import Counter
from typing import Optional

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
    'getgenv', 'getreg', 'getupvalues', 'hookfunction', 'checkcaller',
    'Color3', 'UDim2', 'CFrame', 'Vector2', 'Vector3', 'Enum',
}

VM_SINGLE_LETTERS: dict[str, str] = {
    'R': 'EncStr', 'E': 'GetStr', 'l': 'vmState', 'Q': 'vmStack',
    'I': 'instrTbl', 'w': 'allocSlot', 'M': 'packArgs', 'Y': 'callEnvA',
    'r': 'callEnvB', 'N': 'alphaMap', 'h': 'charFn', 'J': 'funcWrap',
    'S': 'shuffleTbl', 'T': 'tokenMap', 'O': 'cleanRef', 'g': 'helperG',
    'd': 'regD', 'o': 'regO', 'q': 'regQ', 'z': 'regZ', 'G': 'regG',
    'A': 'regA', 'B': 'regB', 'C': 'regC', 'F': 'regF', 'K': 'regK',
    'L': 'regL', 'P': 'regP', 'U': 'regU', 'V': 'regV', 'X': 'regX',
    'Z': 'regZ2', 'a': 'localA', 'b': 'localB', 'c': 'localC', 'f': 'localF',
    'i': 'localI', 'j': 'localJ', 'k': 'localK', 'm': 'localM', 'n': 'localN',
    'p': 'localP', 's': 'localS', 't': 'localT', 'u': 'localU', 'v': 'localV',
    'x': 'localX', 'y': 'localY',
}

SEMANTIC_RENAMES: list[tuple[str, str]] = [
    (r'\bHttpService\b', 'httpService'), (r'\brequestAsync\b', 'httpRequest'),
    (r'\bRequestAsync\b', 'httpRequest'), (r'\bLocalPlayer\b', 'localPlayer'),
    (r'\bCharacter\b', 'playerCharacter'), (r'\bHumanoid\b', 'humanoid'),
    (r'\bloadstring\b', 'dynLoader'), (r'\bload\b(?!\w)', 'dynLoader'),
    (r'\bpcall\b', 'safecall'), (r'\bxpcall\b', 'safecallEx'),
    (r'\bsetmetatable\b', 'setMeta'), (r'\bgetmetatable\b', 'getMeta'),
    (r'\brawset\b', 'rawSet'), (r'\brawget\b', 'rawGet'),
    (r'\bFireServer\b', 'fireServer'), (r'\bFireClient\b', 'fireClient'),
    (r'\bInvokeServer\b', 'invokeServer'), (r'\bFindFirstChild\b', 'findChild'),
    (r'\bWaitForChild\b', 'waitChild'), (r'\bGetService\b', 'getService'),
    (r'\bGetPlayers\b', 'getPlayers'), (r'\bKick\b', 'kickPlayer'),
    (r'\bGetMouse\b', 'getMouse'), (r'\bEncryptedStrings\b', 'strTable'),
    (r'\bGetString\b', 'strGet'), (r'\bVirtualStack\b', 'vmStack'),
    (r'\bInstructionTable\b', 'instrTbl'), (r'\bAllocSlot\b', 'allocSlot'),
    (r'\bPackArgs\b', 'packArgs'), (r'\bCallEnv\b', 'callEnv'),
    (r'\bAlphabetMap\b', 'alphaMap'), (r'\bcharFunc\b', 'charFn'),
    (r'\bFuncWrap\b', 'funcWrap'), (r'\bShuffleTable\b', 'shuffleTbl'),
    (r'\bTokenMap\b', 'tokenMap'), (r'\bCleanupRef\b', 'cleanRef'),
    (r'\bhelperG\b', 'helperG'), (r'\bstateId\b', 'vmState'),
]

def shannon_entropy(data: bytes | bytearray) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def is_lua_bytecode(raw: bytes | bytearray) -> bool:
    return isinstance(raw, (bytes, bytearray)) and raw[:4] == b'\x1bLua'

def is_probably_text(data: str | bytes | bytearray) -> bool:
    if not data:
        return False
    raw = data.encode('latin-1', errors='ignore') if isinstance(data, str) else bytes(data)
    if len(raw) < 6:
        return False
    if is_lua_bytecode(raw):
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    if printable / len(raw) < 0.60:
        return False
    if raw.count(b'\x00') > len(raw) * 0.15:
        return False
    if shannon_entropy(raw) > 7.2:
        return False
    return True

def is_readable_identifier(s: str) -> bool:
    if not s or len(s) > 64:
        return False
    if re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', s):
        return True
    if s in LUA_KEYWORDS:
        return True
    return False

def escape_lua_string(s: str) -> str:
    return json.dumps(s)

def decode_numeric_escapes(s: str) -> str:
    return re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)

def try_base64_decode(s: str) -> Optional[bytes]:
    try:
        s = s.replace('-', '+').replace('_', '/')
        padded = s + '=' * (-len(s) % 4)
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None

def looks_like_real_code(text: str) -> bool:
    if not text or len(text) < 20:
        return False
    lines = text.splitlines()
    keywords = {'function', 'while', 'for', 'if', 'repeat', 'print', 'local', 'return'}
    count = sum(1 for line in lines if any(kw in line for kw in keywords))
    return count >= 1
