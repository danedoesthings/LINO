import math
import random
from typing import Any, Dict, List
from .datatypes import (
    Vector3, Vector2, CFrame, Color3, UDim2, Instance,
    BrickColor, TweenInfo, Ray, Region3, NumberRange,
    PhysicalProperties, Enum, EnumItem
)

class RobloxGlobals:
    def __init__(self, emulator):
        self.emulator = emulator
        self._globals: Dict[str, Any] = {}

    def set(self, name, value):
        self._globals[name] = value

    def get(self, name):
        return self._globals.get(name)

    def setup(self):
        g = self._globals
        em = self.emulator

        g['print'] = lambda *args: em.capture('\t'.join(str(a) for a in args))
        g['error'] = lambda msg, level=0: em.capture(f"[Error] {msg}")
        g['pcall'] = lambda fn, *args: (True, fn(*args)) if callable(fn) else (True, fn)
        g['xpcall'] = lambda fn, errh, *args: (True, fn(*args)) if callable(fn) else (True, fn)
        g['tostring'] = lambda v: 'nil' if v is None else str(v)
        g['tonumber'] = lambda v, base=10: float(v) if v is not None else None
        g['type'] = lambda v: type(v).__name__
        g['select'] = lambda n, *args: len(args) if n == '#' else args[n-1:] if n > 0 else args[n:]
        g['unpack'] = lambda t, i=1, j=None: tuple(t[i-1:j]) if isinstance(t, (list, tuple)) else ()
        g['setmetatable'] = lambda t, mt: t
        g['getmetatable'] = lambda t: None
        g['rawget'] = lambda t, k: t[k] if isinstance(t, dict) and k in t else None
        g['rawset'] = lambda t, k, v: t.__setitem__(k, v) if isinstance(t, dict) else None
        g['rawequal'] = lambda a, b: a == b
        g['next'] = lambda t, k=None: (list(t.keys())[0], t[list(t.keys())[0]]) if t else (None, None)
        g['pairs'] = lambda t: (lambda t: (lambda: None), t, None) if not t else (lambda t, k: (lambda: (None, None))(), t, None)
        g['ipairs'] = lambda t: (lambda: None)
        g['assert'] = lambda v, msg='': None if v else em.capture(f"[Assert] {msg}")
        g['loadstring'] = lambda src, name=None: em._capture_loadstring(src)
        g['load'] = lambda src, name=None: em._capture_loadstring(src)
        g['getfenv'] = lambda lvl=None: g
        g['setfenv'] = lambda fn, env: fn
        g['newproxy'] = lambda addmeta=False: {}
        g['math'] = {
            'floor': math.floor, 'ceil': math.ceil, 'abs': abs,
            'sqrt': math.sqrt, 'random': lambda a=None, b=None: random.random() if a is None else random.randint(int(a), int(b)) if b else random.randint(1, int(a)),
            'pi': math.pi, 'huge': float('inf'), 'sin': math.sin, 'cos': math.cos,
            'min': min, 'max': max, 'pow': math.pow, 'log': math.log,
        }
        g['string'] = {
            'char': lambda *codes: ''.join(chr(int(c) % 256) for c in codes),
            'byte': lambda s, i=1, j=None: (ord(s[i-1]),) if s else (0,),
            'sub': lambda s, i, j=None: s[i-1:j] if s else '',
            'gsub': lambda s, p, r, n=None: (s.replace(p, r), 1) if s else ('', 0),
            'len': lambda s: len(s) if s else 0,
            'gmatch': lambda s, p: iter([]),
            'rep': lambda s, n: s * n,
        }
        g['table'] = {
            'concat': lambda t, sep='', i=1, j=None: sep.join(str(x) for x in t[i-1:j]) if isinstance(t, (list, tuple)) else '',
            'insert': lambda t, pos, val=None: t.append(pos) if val is None else t.insert(pos-1, val),
            'remove': lambda t, pos=None: t.pop(pos-1) if pos else t.pop(),
        }
        g['bit32'] = {
            'bxor': lambda a, b: a ^ b,
            'band': lambda a, b: a & b,
            'bor': lambda a, b: a | b,
            'lshift': lambda v, n: (v << n) & 0xFFFFFFFF,
            'rshift': lambda v, n: v >> n,
        }
        g['bit'] = g['bit32']
        g['coroutine'] = {
            'wrap': lambda f: f,
            'create': lambda f: f,
            'resume': lambda co, *args: (True, co(*args)) if callable(co) else (True, None),
            'yield': lambda: None,
        }
        g['os'] = {'time': lambda: 0, 'clock': lambda: 0, 'date': lambda: ''}
        g['tick'] = lambda: 0
        g['time'] = lambda: 0
        g['wait'] = lambda n=None: None
        g['spawn'] = lambda f: f() if callable(f) else None
        g['delay'] = lambda t, f: f() if callable(f) else None
        g['require'] = lambda id: Instance(str(id), em)
        g['script_key'] = "c4ce76cd36f2afee4dcee7e87576e5fa"
        g['game'] = Instance('game', em)
        g['workspace'] = Instance('workspace', em)
        g['script'] = Instance('script', em)
        g['shared'] = {}
        g['_G'] = g
        g['_ENV'] = g
        g['_VERSION'] = 'Luau'
        g['Vector3'] = Vector3
        g['Vector2'] = Vector2
        g['CFrame'] = CFrame
        g['Color3'] = Color3
        g['UDim2'] = UDim2
        g['Instance'] = Instance
        g['BrickColor'] = BrickColor
        g['TweenInfo'] = TweenInfo
        g['Ray'] = Ray
        g['Region3'] = Region3
        g['NumberRange'] = NumberRange
        g['PhysicalProperties'] = PhysicalProperties
        g['Enum'] = Enum('Enum')
        g['getgenv'] = lambda: g
        g['getrenv'] = lambda: g
        g['identifyexecutor'] = lambda: ('Synapse X', '2.0')
        g['getexecutorname'] = lambda: 'Synapse X'
        g['getrawmetatable'] = lambda t: None
        g['setrawmetatable'] = lambda t, m: t
        g['gethui'] = lambda: Instance('HUI', em)
        g['getnilinstances'] = lambda: []
        g['getinstances'] = lambda: []
        g['getgc'] = lambda: []
        g['getreg'] = lambda: {}
        g['getloadedmodules'] = lambda: {}
        g['getconnections'] = lambda: {}
        g['hookfunction'] = lambda f, h: f
        g['hookmetamethod'] = lambda o, m, f: lambda: None
        g['newcclosure'] = lambda f: f
        g['clonefunction'] = lambda f: f
        g['iscclosure'] = lambda: False
        g['islclosure'] = lambda: True
        g['checkcaller'] = lambda: True
        g['isnetworkowner'] = lambda: True
        g['readfile'] = lambda f: ''
        g['writefile'] = lambda f, c: None
        g['appendfile'] = lambda f, c: None
        g['loadfile'] = lambda f: lambda: None
        g['isfile'] = lambda: False
        g['isfolder'] = lambda: False
        g['makefolder'] = lambda: None
        g['delfolder'] = lambda: None
        g['delfile'] = lambda: None
        g['listfiles'] = lambda: []
        g['rconsoleprint'] = lambda msg: em.capture(msg)
        g['rconsoleinfo'] = lambda msg: em.capture(msg)
        g['rconsolewarn'] = lambda msg: em.capture(msg)
        g['rconsoleerr'] = lambda msg: em.capture(msg)
        g['rconsoleclear'] = lambda: None
        g['iswindowactive'] = lambda: True
        g['setclipboard'] = lambda s: None
        g['toclipboard'] = lambda s: None
        g['getclipboard'] = lambda: ''
        g['setfpscap'] = lambda c: None
        g['getfpscap'] = lambda: 240
        g['getping'] = lambda: 50
        g['messagebox'] = lambda t, m, b: 1
        g['request'] = lambda o: {'StatusCode': 200, 'Body': '--PAYLOAD--', 'Headers': {}}
        g['http_request'] = g['request']
        g['crypt'] = {
            'encrypt': lambda d: d,
            'decrypt': lambda d: d,
            'hash': lambda d: 'hash',
            'generatekey': lambda: 'key',
            'base64encode': lambda d: d,
            'base64decode': lambda d: d,
        }
        for name in ['syn', 'krnl', 'fluxus', 'sw', 'electron', 'synapse', 'solara', 'codex', 'scriptware', 'aris', 'trigon', 'nexus', 'wave', 'kiro', 'hydrogen', 'delta', 'ev0n', 'vega_x', 'valyse', 'sentinel', 'aurora', 'cerberus', 'jjsploit', 'xenon', 'calamari', 'mars', 'oxygen_u', 'velvet', 'frostbite', 'luna', 'rogue', 'sova', 'eulen', 'sirhurt', 'proxo', 'furk_os', 'shark']:
            g[name] = g
        g['debug'] = {
            'getinfo': lambda fn=None, w=None: {'source': '[C]', 'short_src': '[C]', 'what': 'C'},
            'getconstants': lambda: [],
            'getconstant': lambda: None,
            'setconstant': lambda: None,
            'getupvalues': lambda: [],
            'getupvalue': lambda: None,
            'setupvalue': lambda: None,
            'getprotos': lambda: [],
            'getproto': lambda: None,
            'getstack': lambda: [],
            'setstack': lambda: None,
            'getregistry': lambda: {},
            'getmetatable': lambda t: None,
            'setmetatable': lambda t, m: t,
            'traceback': lambda msg=None, lvl=None: '[string "chunk"]:1: in function <chunk:1>',
            'sethook': lambda: None,
            'gethook': lambda: (None, '', 0),
            'getlocal': lambda: None,
            'setlocal': lambda: None,
            'getfenv': lambda: g,
            'setfenv': lambda: None,
        }
        g['task'] = {
            'wait': lambda n=None: None,
            'spawn': lambda f: f() if callable(f) else None,
            'defer': lambda f: f() if callable(f) else None,
            'delay': lambda t, f: f() if callable(f) else None,
        }

    def _capture_loadstring(self, src):
        if isinstance(src, str):
            self.emulator.capture(src)
            self.emulator.capture(f"[Payload: {len(src)} bytes]")
        return lambda: None, None
