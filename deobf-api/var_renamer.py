import re
from typing import Dict, List, Optional, Tuple

_VM_SINGLE_LETTER: Dict[str, str] = {
    'R': 'EncryptedStrings',
    'E': 'GetString',
    'l': 'stateId',
    'Q': 'VirtualStack',
    'I': 'InstructionTable',
    'w': 'AllocSlot',
    'M': 'PackArgs',
    'Y': 'CallEnv',
    'N': 'AlphabetMap',
    'h': 'charFunc',
    'J': 'FuncWrap',
    'S': 'ShuffleTable',
    'T': 'TokenMap',
    'O': 'CleanupRef',
    'g': 'HelperFunc',
    'z': 'regZ',
    'q': 'regQ',
    'd': 'regD',
    'o': 'regO',
    'n': 'regN',
    'c': 'regC',
    'F': 'regF',
    'b': 'regB',
    'j': 'regJ',
    'D': 'regD2',
    'A': 'regA',
    'L': 'regL',
    'C': 'regC2',
    'G': 'regG',
    't': 'tempVal',
    'p': 'ptrVal',
    'X': 'xVal',
    'k': 'keyVal',
    'H': 'slotH',
    'U': 'slotU',
    'V': 'retVal',
    'P': 'ptrP',
    'Z': 'ptrZ',
    'B': 'baseB',
    'K': 'indexK',
    'a': 'tableA',
    'f': 'funcRef',
    'i': 'iterI',
    's': 'strS',
    'u': 'uVal',
    'v': 'vRef',
    'x': 'xRef',
    'y': 'yRef',
    'r': 'argList',
    'm': 'metaM',
    'e': 'envWrap',
}

_CONTEXT_PATTERNS: List[Tuple[str, str]] = [
    (r'\bHttpService\b', 'httpService'),
    (r'\bRequestAsync\b', 'httpRequest'),
    (r'\bHttpGet\b', 'httpGet'),
    (r'\bHttpPost\b', 'httpPost'),
    (r'\brequest\b', 'httpResponse'),
    (r'\bresponse\b', 'httpResponse'),
    (r'\bLocalPlayer\b', 'localPlayer'),
    (r'\bCharacter\b', 'character'),
    (r'\bHumanoid\b', 'humanoid'),
    (r'\bHumanoidRootPart\b', 'rootPart'),
    (r'\bHead\b', 'playerHead'),
    (r'\bloadstring\b', 'loadedFunc'),
    (r'\bload\b', 'loadedFunc'),
    (r'\bloadfile\b', 'loadedFunc'),
    (r'\bpcall\b', 'protectedCall'),
    (r'\bxpcall\b', 'protectedCallEx'),
    (r'\bWorkspace\b', 'workspace'),
    (r'\bRunService\b', 'runService'),
    (r'\bTweenService\b', 'tweenService'),
    (r'\bUserInputService\b', 'inputService'),
    (r'\bReplicatedStorage\b', 'replicatedStorage'),
    (r'\bServerStorage\b', 'serverStorage'),
    (r'\bStarterGui\b', 'starterGui'),
    (r'\bLighting\b', 'lighting'),
    (r'\bSoundService\b', 'soundService'),
    (r'\bbase64\b', 'b64Codec'),
    (r'\balphabet\b', 'b64Alphabet'),
    (r'\bxor\b', 'xorFunc'),
    (r'\bbitwise\b', 'bitwiseOp'),
    (r'\bgetService\b', 'getService'),
    (r'\bFindFirstChild\b', 'findChild'),
    (r'\bWaitForChild\b', 'waitChild'),
    (r'\bGetChildren\b', 'getChildren'),
    (r'\bclone\b', 'cloneObj'),
    (r'\bDestroy\b', 'destroyObj'),
    (r'\bFireServer\b', 'fireServer'),
    (r'\bFireClient\b', 'fireClient'),
    (r'\bInvokeServer\b', 'invokeServer'),
    (r'\bInvokeClient\b', 'invokeClient'),
]

_REGISTER_PATTERN = re.compile(r'\br(\d{2,3})\b')

_OBFUSCATED_ID = re.compile(r'^[a-zA-Z][0-9]{3,}$|^[A-Z]{4,8}$|^[a-z][A-Z][0-9]+$')

def _make_register_name(num: int) -> str:
    known = {
        0: 'argSelf',
        1: 'argFirst',
        2: 'argSecond',
        3: 'argThird',
        4: 'argFourth',
        5: 'argFifth',
        6: 'argSixth',
        7: 'argSeventh',
        8: 'argEighth',
        9: 'argNinth',
        10: 'argTenth',
    }
    if num in known:
        return known[num]
    return f'reg{num}'

def _infer_semantic_name(identifier: str, context_window: str) -> Optional[str]:
    for pattern, hint in _CONTEXT_PATTERNS:
        if re.search(pattern, context_window, re.IGNORECASE):
            return hint
    m = re.search(
        r'local\s+' + re.escape(identifier) + r'\s*=\s*(\w+)',
        context_window
    )
    if m:
        rhs = m.group(1)
        if rhs[0].isupper():
            return rhs[0].lower() + rhs[1:]
    return None

def _safe_word_boundary_replace(code: str, old: str, new: str) -> str:
    return re.sub(r'\b' + re.escape(old) + r'\b', new, code)

class VarRenamer:
    def __init__(self):
        self._custom_map: Dict[str, str] = {}

    def add_custom_mapping(self, old: str, new: str) -> None:
        self._custom_map[old] = new

    def rename(self, code: str) -> str:
        code = self._apply_vm_single_letters(code)
        code = self._apply_register_names(code)
        code = self._apply_context_hints(code)
        code = self._apply_custom_map(code)
        code = self._apply_obfuscated_ids(code)
        code = self._cleanup_noise(code)
        return code

    def _apply_vm_single_letters(self, code: str) -> str:
        for short, readable in _VM_SINGLE_LETTER.items():
            if len(short) == 1:
                code = re.sub(
                    r'(?<![a-zA-Z0-9_])' + re.escape(short) + r'(?![a-zA-Z0-9_])',
                    readable,
                    code
                )
            else:
                code = _safe_word_boundary_replace(code, short, readable)
        return code

    def _apply_register_names(self, code: str) -> str:
        def repl(m: re.Match) -> str:
            num = int(m.group(1))
            return _make_register_name(num)
        return _REGISTER_PATTERN.sub(repl, code)

    def _apply_context_hints(self, code: str) -> str:
        lines = code.split('\n')
        out = []
        for i, line in enumerate(lines):
            window = '\n'.join(lines[max(0, i-3):i+4])
            extra_hints = []
            for pattern, hint in _CONTEXT_PATTERNS:
                if re.search(pattern, line):
                    extra_hints.append(hint)
            if extra_hints and '--' not in line:
                unique = list(dict.fromkeys(extra_hints))[:3]
                line = line + '  -- [RENAME HINT] ' + ', '.join(unique)
            out.append(line)
        return '\n'.join(out)

    def _apply_custom_map(self, code: str) -> str:
        for old, new in self._custom_map.items():
            code = _safe_word_boundary_replace(code, old, new)
        return code

    def _apply_obfuscated_ids(self, code: str) -> str:
        obf_id_pat = re.compile(r'\b([A-Za-z][0-9]{5,})\b')
        def repl(m: re.Match) -> str:
            ident = m.group(1)
            return f'_obf_{ident}'
        code = obf_id_pat.sub(repl, code)
        return code

    def _cleanup_noise(self, code: str) -> str:
        code = re.sub(r'\s*--\s*\d{4,}\s*(?=\n|$)', '', code)
        code = re.sub(r'\n{3,}', '\n\n', code)
        code = '\n'.join(l.rstrip() for l in code.split('\n'))
        return code
