import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio, struct, hashlib, json, time, traceback, binascii, sys, math, resource
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Union, Any
from enum import Enum

try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

LUA_KEYWORDS = {
    'function', 'local', 'end', 'return', 'if', 'then', 'else', 'elseif',
    'for', 'while', 'do', 'repeat', 'until', 'not', 'and', 'or',
    'nil', 'true', 'false', 'in', 'break', 'print', 'require',
    'pcall', 'xpcall', 'loadstring', 'load', 'pairs', 'ipairs',
    'setmetatable', 'getmetatable', 'rawset', 'rawget', 'tostring', 'tonumber',
    'table', 'string', 'math', 'coroutine', 'debug', 'io', 'os',
    'unpack', 'select', 'type', 'assert', 'error', 'next', 'rawequal',
}


def _find_balanced_end(content, open_brace_index):
    depth = 0
    quote = None
    in_long_string = False
    long_match = None
    idx = open_brace_index
    while idx < len(content):
        char = content[idx]
        if in_long_string:
            if char == ']' and content[idx:idx+len(long_match)] == long_match:
                in_long_string = False
                idx += len(long_match)
                continue
            idx += 1
            continue
        if quote:
            if char == '\\':
                idx += 2
                continue
            if char == quote:
                quote = None
            idx += 1
            continue
        if char == '[':
            m = re.match(r'\[=*\[', content[idx:])
            if m:
                long_match = ']' + m.group(0)[2:-1] + ']'
                in_long_string = True
                idx += len(m.group(0))
                continue
        if char in ("'", '"'):
            quote = char
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return idx + 1
        idx += 1
    return -1


def _get_all_table_bodies(source):
    bodies = []
    idx = 0
    while idx < len(source):
        brace_pos = source.find('{', idx)
        if brace_pos == -1:
            break
        end = _find_balanced_end(source, brace_pos)
        if end != -1:
            bodies.append(source[brace_pos:end])
            idx = end
        else:
            idx = brace_pos + 1
    return bodies


def _extract_strings_from_table_body(body):
    strings = []
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', body):
        strings.append(m.group(1))
    for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", body):
        strings.append(m.group(1))
    return strings


def _lua_unescape(s):
    result = bytearray()
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            nc = s[i+1]
            if nc == 'n': result.append(0x0A); i += 2
            elif nc == 'r': result.append(0x0D); i += 2
            elif nc == 't': result.append(0x09); i += 2
            elif nc == '\\': result.append(0x5C); i += 2
            elif nc == '"': result.append(0x22); i += 2
            elif nc == "'": result.append(0x27); i += 2
            elif nc == 'a': result.append(0x07); i += 2
            elif nc == 'b': result.append(0x08); i += 2
            elif nc == 'f': result.append(0x0C); i += 2
            elif nc == 'v': result.append(0x0B); i += 2
            elif nc == 'x' and i + 3 < len(s):
                try: result.append(int(s[i+2:i+4], 16)); i += 4
                except: result.append(ord('?')); i += 4
            elif nc.isdigit():
                j = i + 1
                while j < len(s) and s[j].isdigit() and j - (i + 1) < 3: j += 1
                try: val = int(s[i+1:j]); result.append(val % 256)
                except: pass
                i = j
            else: result.append(ord(nc) if ord(nc) < 256 else 0x3F); i += 2
        else:
            b = ord(s[i])
            if b <= 0x7F: result.append(b)
            elif b <= 0x7FF: result.append(0xC0 | (b>>6)); result.append(0x80 | (b & 0x3F))
            elif b <= 0xFFFF: result.append(0xE0 | (b>>12)); result.append(0x80 | ((b>>6) & 0x3F)); result.append(0x80 | (b & 0x3F))
            else: result.append(0xF0 | (b>>18)); result.append(0x80 | ((b>>12) & 0x3F)); result.append(0x80 | ((b>>6) & 0x3F)); result.append(0x80 | (b & 0x3F))
            i += 1
    return bytes(result)


def _decode_custom_base64(data, alphabet):
    rev_map = {}
    for i, entry in enumerate(alphabet, start=1):
        if entry and len(entry) == 1:
            rev_map[entry] = i
    if len(rev_map) < 20:
        return None
    buf, bits, out = 0, 0, bytearray()
    for b in data:
        ch = chr(b) if b < 256 else ''
        if ch == '=': break
        if ch not in rev_map: continue
        buf = (buf << 6) | rev_map[ch]
        bits += 6
        while bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
    return bytes(out)


def _extract_shuffle_ranges(source):
    ranges = []
    for m in re.finditer(r'for\s+(\w+)\s*=\s*(\d+)\s*,\s*(\d+)\s*do', source):
        try:
            start_val = int(m.group(2))
            end_val = int(m.group(3))
            body_start = source.find('do', m.end())
            if body_start == -1: continue
            end_pos = source.find('end', body_start)
            if end_pos == -1: continue
            inner = source[body_start+2:end_pos]
            if re.search(r'\w+\[\w+\]\s*=\s*\w+\[\w+\]', inner):
                ranges.append((start_val, end_val))
        except: continue
    return ranges


def _looks_like_lua(code):
    if not code or len(code) < 50: return False
    keywords = {'function','local','end','if','then','return','for','while','do','nil','true','false'}
    words = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', code[:2000]))
    if len(words & keywords) < 2: return False
    return True


class DeobfEngine:
    def __init__(self):
        self.unluac_path = UNLUAC_LOCAL_PATH
        self.capabilities = {'static_extraction','custom_base64','shuffle_recovery','lua_runtime_harness'}
        self._java_available = shutil.which('java') is not None

    def get_capabilities(self):
        return list(self.capabilities)

    def _run_lua_harness(self, source):
        harness = r'''
local captures = {}
local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function b64encode(data)
    local result = {}
    local padding = ""
    for i = 1, #data, 3 do
        local a,b,c = data:byte(i,i+2)
        b = b or 0; c = c or 0
        local n = a*65536 + b*256 + c
        local c1 = math.floor(n/262144)%64
        local c2 = math.floor(n/4096)%64
        local c3 = math.floor(n/64)%64
        local c4 = n%64
        table.insert(result, b64chars:sub(c1+1,c1+1))
        table.insert(result, b64chars:sub(c2+1,c2+1))
        if i+1 > #data then padding="=="; break end
        table.insert(result, b64chars:sub(c3+1,c3+1))
        if i+2 > #data then padding="="; break end
        table.insert(result, b64chars:sub(c4+1,c4+1))
    end
    return table.concat(result)..padding
end
local function save(tag, data)
    if type(data) ~= "string" then return end
    if #data < 20 then return end
    local encoded = b64encode(data)
    table.insert(captures, {tag=tag, data=encoded})
end
local orig_loadstring = loadstring
_G.loadstring = function(code, chunkname)
    save("loadstring", code)
    return orig_loadstring(code, chunkname)
end
if load then
    local orig_load = load
    _G.load = function(code, chunkname)
        save("load", code)
        return orig_load(code, chunkname)
    end
end
local f, err = loadfile("_SRCFILE_")
if not f then
    print("ERR:COMPILE:"..tostring(err))
    return
end
local success, result = pcall(f)
if #captures > 0 then
    for _, cap in ipairs(captures) do
        print("CAP:"..cap.tag..":"..cap.data)
    end
    return
end
if not success then
    print("ERR:RUNTIME:"..tostring(result))
else
    print("ERR:NO_OUTPUT")
end
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as src_tmp:
            src_tmp.write(source)
            src_path = src_tmp.name
        harness = harness.replace('_SRCFILE_', src_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False, encoding='utf-8') as tmp:
            tmp.write(harness)
            tmp_path = tmp.name
        captures = []
        errors = []
        try:
            for lua_bin in ['lua5.1', 'lua']:
                try:
                    result = subprocess.run([lua_bin, tmp_path], capture_output=True, timeout=30)
                    stdout = result.stdout.decode('latin-1', errors='replace')
                    stderr = result.stderr.decode('latin-1', errors='replace')
                    for line in stdout.splitlines():
                        if line.startswith('CAP:'): captures.append(line[4:])
                        elif line.startswith('ERR:'): errors.append(line[4:])
                    for line in stderr.splitlines():
                        if line.strip(): errors.append(line.strip())
                    if captures or errors: break
                except FileNotFoundError: continue
                except subprocess.TimeoutExpired: errors.append("timeout"); break
        finally:
            try: os.unlink(tmp_path)
            except OSError: pass
            try: os.unlink(src_path)
            except OSError: pass
        if captures:
            best = None
            for cap in captures:
                if ':' in cap:
                    tag, data = cap.split(':', 1)
                else:
                    data = cap
                try:
                    decoded = base64.b64decode(data).decode('latin-1', errors='replace')
                    if _looks_like_lua(decoded):
                        best = decoded
                        break
                except: pass
            if best: return best, None
            try:
                first = captures[0]
                if ':' in first: first = first.split(':', 1)[1]
                raw = base64.b64decode(first).decode('latin-1', errors='replace')
                return raw, None
            except: pass
            return None, 'no readable captures'
        return None, '; '.join(errors) if errors else 'no output'

    def process(self, source):
        diags = []
        bodies = _get_all_table_bodies(source)
        encoded_strings = None
        alphabet = None
        for body in bodies:
            strings = _extract_strings_from_table_body(body)
            if len(strings) >= 10:
                avg_len = sum(len(s) for s in strings) / len(strings)
                if avg_len > 10:
                    encoded_strings = strings
                    diags.append(f"data table: {len(strings)} strs, avg_len {avg_len:.1f}")
                if avg_len <= 2 and len(strings) >= 30:
                    unescaped = []
                    for s in strings:
                        raw = _lua_unescape(s)
                        if len(raw) == 1:
                            unescaped.append(chr(raw[0]))
                    if len(unescaped) >= 20:
                        alphabet = unescaped
                        diags.append(f"alphabet table: {len(unescaped)} chars")
        if encoded_strings and alphabet:
            shuffle_ranges = _extract_shuffle_ranges(source)
            working = list(encoded_strings)
            if shuffle_ranges:
                for lo, hi in shuffle_ranges:
                    lo_idx, hi_idx = lo - 1, hi - 1
                    if 0 <= lo_idx < len(working) and 0 <= hi_idx < len(working) and lo_idx < hi_idx:
                        working[lo_idx:hi_idx+1] = working[lo_idx:hi_idx+1][::-1]
            decoded_chunks = []
            for s in working:
                raw = _lua_unescape(s)
                if raw:
                    dec = _decode_custom_base64(raw, alphabet)
                    if dec:
                        decoded_chunks.append(dec)
            if decoded_chunks:
                combined = b''.join(decoded_chunks)
                for enc in ('utf-8', 'latin-1'):
                    try:
                        text = combined.decode(enc)
                        text = ''.join(ch for ch in text if ch.isprintable() or ch in '\n\r\t')
                        if len(text) > 100 and _looks_like_lua(text):
                            beautified = text.strip()
                            return beautified, 'static_decode', f'Static decode ({len(beautified)} chars)', []
                    except: pass
                raw_text = combined.decode('latin-1', errors='replace')
                return raw_text, 'static_decode_raw', f'Raw static decode ({len(raw_text)} chars)', []

        harness_result, harness_error = self._run_lua_harness(source)
        if harness_result:
            return harness_result, 'lua_harness', 'Runtime capture', []
        elif harness_error:
            diags.append(f"harness: {harness_error[:200]}")
        return '', 'unable', '; '.join(diags) if diags else 'All strategies failed', []
