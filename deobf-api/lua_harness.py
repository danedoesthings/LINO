import base64, os, re, signal, subprocess, sys, tempfile
from typing import Optional
from constants import LUA_KEYWORDS, is_probably_text, is_lua_bytecode

_HARNESS = r'''
local _captures = {}
local _CALL_DEPTH = 0
local _MAX_DEPTH  = 25
local _b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function b64enc(data)
    local r, p = {}, ''
    for i = 1, #data, 3 do
        local a, b, c = data:byte(i, i+2)
        b = b or 0; c = c or 0
        local n = a*65536 + b*256 + c
        local c1 = math.floor(n/262144)%64
        local c2 = math.floor(n/4096)%64
        local c3 = math.floor(n/64)%64
        local c4 = n%64
        r[#r+1] = _b64:sub(c1+1,c1+1)
        r[#r+1] = _b64:sub(c2+1,c2+1)
        if i+1>#data then p='=='; break end
        r[#r+1] = _b64:sub(c3+1,c3+1)
        if i+2>#data then p='='; break end
        r[#r+1] = _b64:sub(c4+1,c4+1)
    end
    return table.concat(r)..p
end

local _real_insert = table.insert
local function _save(tag, data)
    if type(data) ~= 'string' or #data < 20 then return end
    if _CALL_DEPTH > _MAX_DEPTH then return end
    _CALL_DEPTH = _CALL_DEPTH + 1
    _real_insert(_captures, tag .. ':' .. b64enc(data))
    _CALL_DEPTH = _CALL_DEPTH - 1
end

local _real_ls = loadstring
local _real_load = load or loadstring
local _in_load = false
_G.loadstring = function(code, ...)
    if not _in_load then _in_load=true; _save('loadstring', code); _in_load=false end
    return _real_ls(code, ...)
end
if load ~= loadstring then
    _G.load = function(code, ...)
        if not _in_load then _in_load=true; _save('load', tostring(code)); _in_load=false end
        return _real_load(code, ...)
    end
end

local _real_char = string.char
string.char = function(...)
    local out = _real_char(...)
    if #out > 40 then _save('string.char', out) end
    return out
end

local _real_concat = table.concat
table.concat = function(t, sep, i, j)
    local out = _real_concat(t, sep, i, j)
    if type(out)=='string' and #out>20 then _save('table.concat', out) end
    return out
end

local _print_lines = {}
local _real_print = print
_G.print = function(...)
    local parts = {}
    for i=1, select('#',...) do parts[i] = tostring(select(i,...)) end
    _real_insert(_print_lines, table.concat(parts, '\t'))
end

os.execute  = function() error('os.execute blocked') end
io.popen    = function() error('io.popen blocked') end

if not getfenv then
    getfenv = function(f)
        if f then
            local i=1
            while true do
                local name,val = debug.getupvalue(f,i)
                if not name then break end
                if name=='_ENV' then return val end
                i=i+1
            end
        end
        return _G
    end
end
if not newproxy    then newproxy    = function(m) local p={} if m then setmetatable(p,{}) end return p end end
if not unpack      then unpack      = table.unpack end
if not getreg      then getreg      = function() return {} end end
if not hookfunction then hookfunction = function(f,h) return h end end
if not checkcaller then checkcaller  = function() return false end end
if not bit then _G.bit = _G.bit32 end

local function _stub_tbl()
    return setmetatable({}, {
        __index    = function() return _stub_tbl() end,
        __call     = function() return _stub_tbl() end,
        __newindex = function(t,k,v) rawset(t,k,v) end,
    })
end
if not game      then game      = _stub_tbl() end
if not workspace then workspace = _stub_tbl() end
if not Instance  then Instance  = {new = function() return _stub_tbl() end} end
if not task      then task      = {spawn=function(f) pcall(f) end, delay=function(_,f) pcall(f) end, wait=function() end} end
if not typeof    then typeof    = type end
if not getgenv   then getgenv   = function() return _G end end
if not Enum      then Enum      = _stub_tbl() end
if not Color3    then Color3    = {new=function() return {} end, fromRGB=function() return {} end} end
if not UDim2     then UDim2     = {new=function() return {} end} end
if not CFrame    then CFrame    = {new=function() return {} end, lookAt=function() return {} end} end
if not Vector2   then Vector2   = {new=function() return {} end} end
if not Vector3   then Vector3   = {new=function() return {} end} end

if not bit32 then
    local function bxor(a,b) local r,m=0,1; while a>0 or b>0 do if a%2~=b%2 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    local function band(a,b) local r,m=0,1; while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    local function bor(a,b)  local r,m=0,1; while a>0 or b>0 do if a%2+b%2>0 then r=r+m end; a=math.floor(a/2); b=math.floor(b/2); m=m*2 end; return r end
    bit32 = {bxor=bxor, band=band, bor=bor,
             lshift=function(v,n) return math.floor(v*(2^n))%4294967296 end,
             rshift=function(v,n) return math.floor(v/(2^n)) end}
    bit32.arshift = bit32.rshift
    _G.bit32 = bit32; _G.bit = bit32
end

local _f, _err = loadfile('__SRCFILE__')
if not _f then
    _real_print('ERR:COMPILE:' .. tostring(_err))
else
    local _ok, _result = pcall(_f)
    collectgarbage('collect')
    pcall(function()
        for k,v in pairs(_G) do
            if type(v)=='string' and #v>20 then _save('global_'..tostring(k), v) end
        end
    end)
    for _,cap in ipairs(_captures) do _real_print('CAP:' .. cap) end
    if #_print_lines > 0 then
        _real_print('CAP:print_output:' .. b64enc(table.concat(_print_lines, '\n')))
    end
    if #_captures == 0 and #_print_lines == 0 then
        if not _ok then _real_print('ERR:RUNTIME:' .. tostring(_result))
        else _real_print('ERR:NO_OUTPUT') end
    end
end
'''

def _find_lua() -> Optional[str]:
    import shutil
    for candidate in ('lua5.1', 'lua5.2', 'lua', 'lua5.4', 'lua5.3'):
        if shutil.which(candidate):
            return candidate
    return None

def _set_limits() -> None:
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 65))
        resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))
    except Exception:
        pass

class LuaHarness:
    def __init__(self, unluac_path: Optional[str] = None) -> None:
        self.lua_bin = _find_lua()
        self.unluac_path = unluac_path
        self.available = self.lua_bin is not None

    def run(self, source: str, timeout: int = 90) -> Optional[str]:
        if not self.available:
            return None
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as sf:
            sf.write(source)
            src_path = sf.name
        harness = _HARNESS.replace('__SRCFILE__', src_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as hf:
            hf.write(harness)
            harness_path = hf.name
        captures: list[str] = []
        try:
            proc = subprocess.Popen(
                [self.lua_bin, harness_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=_set_limits, start_new_session=True,
            )
            try:
                stdout, _ = proc.communicate(timeout=timeout)
                stdout = stdout.decode('latin-1', errors='replace')
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
                stdout = ''
            proc.wait()
            for line in stdout.splitlines():
                if line.startswith('CAP:'):
                    captures.append(line[4:])
        finally:
            for p in (harness_path, src_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        if not captures:
            return None
        return self._pick_best(captures)

    def _pick_best(self, captures: list[str]) -> Optional[str]:
        candidates: list[dict] = []
        for cap in captures:
            tag, _, b64 = cap.partition(':')
            try:
                raw = base64.b64decode(b64).decode('latin-1', errors='replace')
            except Exception:
                raw = b64
            if tag == 'print_output':
                if raw.strip():
                    candidates.append({'data': raw, 'score': len(raw)})
                continue
            if is_probably_text(raw):
                kw_hits = sum(1 for kw in LUA_KEYWORDS if kw in raw)
                candidates.append({'data': raw, 'score': len(raw) + kw_hits * 20})
            elif is_lua_bytecode(raw.encode('latin-1', errors='ignore')):
                dec = self._decompile_bytecode(raw.encode('latin-1', errors='ignore'))
                if dec:
                    candidates.append({'data': dec, 'score': len(dec) + 500})
        if not candidates:
            return None
        return max(candidates, key=lambda x: x['score'])['data']

    def _decompile_bytecode(self, bc: bytes) -> Optional[str]:
        if not self.unluac_path or not os.path.isfile(self.unluac_path):
            return None
        import shutil
        if not shutil.which('java'):
            return None
        with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
            tmp.write(bc)
            tmp_path = tmp.name
        try:
            r = subprocess.run(
                ['java', '-jar', self.unluac_path, '--rawstring', tmp_path],
                capture_output=True, timeout=30,
            )
            if r.returncode == 0:
                return r.stdout.decode('latin-1', errors='replace')
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return None
