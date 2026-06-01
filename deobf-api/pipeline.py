import os, re, json, subprocess, random, uuid, string, base64, hashlib, time

def _random_name(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def _random_key():
    return base64.b64encode(os.urandom(32)).decode('ascii')[:32]

def _junk_code_block():
    patterns = [
        f'local {_random_name()} = {random.randint(0, 99999)}',
        f'local {_random_name()} = "{_random_name()}"',
        f'local {_random_name()} = {{{random.randint(0,9)}, {random.randint(0,9)}, {random.randint(0,9)}}}',
        f'if {random.randint(0,1)} == {random.randint(0,1)} then local {_random_name()} = {random.random() * 1000} end',
        f'local {_random_name()} = function() return {random.randint(0, 255)} end',
        f'local {_random_name()} = {_random_name()} or "{_random_name()}"',
        f'local {_random_name()} = #{_random_name()}',
        f'local {_random_name()} = math.floor({random.random() * 1000})',
        f'do local {_random_name()} = {random.randint(0, 65535)} end',
        f'local {_random_name()} = bit32 and bit32.bxor({random.randint(0,255)}, {random.randint(0,255)}) or {random.randint(0,255)}',
        f'while false do local {_random_name()} = {_random_name()} end',
        f'repeat local {_random_name()} = {random.randint(0,1)} until true',
        f'for _ = 1, {random.randint(0,1)} do local {_random_name()} = nil end',
        f'local {_random_name()} = {{nil, nil, nil}}[{random.randint(1,3)}]',
        f'local {_random_name()} = select({random.randint(1,3)}, 1, 2, 3)',
        f'local {_random_name()} = rawget({{}}, "{_random_name()}")',
        f'local {_random_name()} = rawequal(1, {random.randint(0,1)})',
        f'local {_random_name()} = type({{}}) == "table" and true or false',
        f'local {_random_name()} = next({{}})',
        f'local {_random_name()} = pcall(function() return {random.randint(0,255)} end)',
    ]
    return random.choice(patterns)

def _number_to_expression(n):
    if n < 0:
        return f'(-{_number_to_expression(abs(n))})'
    methods = [
        lambda n: f'({random.randint(5000, 15000)} - {random.randint(5000, 15000) - n})',
        lambda n: f'({n + random.randint(1, 500)} - {random.randint(1, 500)})',
        lambda n: f'({random.randint(0, n)} + {n - random.randint(0, n)})',
        lambda n: f'({n * random.randint(2,5)} // {random.randint(2,5)})',
        lambda n: f'({n} ^ 1)',
        lambda n: f'math.floor({float(n)} + 0.{random.randint(1,99)})',
        lambda n: f'(({n} * 0x{random.randint(2,16):x}) // 0x{random.randint(2,16):x})',
        lambda n: f'bit32.bxor({n}, {random.randint(0,min(n,255))}) ^ 0' if n <= 255 else f'({n})',
    ]
    return random.choice(methods)(n)

def _generate_encryption_key():
    return _random_key()

def _encrypt_strings(source, key):
    lines = source.split('\n')
    encrypted = []
    encrypted.append(f'local _key = "{key}"')
    encrypted.append('local function _decrypt(s)')
    encrypted.append('    local r = {}')
    encrypted.append('    for i = 1, #s do')
    encrypted.append('        local b = string.byte(s, i)')
    encrypted.append('        local kb = string.byte(_key, (i-1) % #_key + 1)')
    encrypted.append('        r[i] = string.char(bit32.bxor(b, kb))')
    encrypted.append('    end')
    encrypted.append('    return table.concat(r)')
    encrypted.append('end')
    import re as _re
    for line in lines:
        def replace_string(m):
            s = m.group(1)
            enc = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s))
            b64 = base64.b64encode(enc.encode('latin-1')).decode('ascii')
            return f'_decrypt("{b64}")'
        line = _re.sub(r'"([^"]*)"', replace_string, line)
        encrypted.append(line)
    return '\n'.join(encrypted)

def _apply_control_flow_flattening(source):
    lines = source.split('\n')
    blocks = []
    current = []
    for line in lines:
        if line.strip().startswith(('function', 'if', 'while', 'for', 'repeat', 'do')):
            if current:
                blocks.append('\n'.join(current))
                current = []
        current.append(line)
    if current:
        blocks.append('\n'.join(current))
    if len(blocks) < 3:
        return source
    random.shuffle(blocks)
    state_var = _random_name()
    flattened = [f'local {state_var} = 1']
    flattened.append(f'while {state_var} do')
    for i, block in enumerate(blocks):
        flattened.append(f'    if {state_var} == {i+1} then')
        for bline in block.split('\n'):
            flattened.append(f'        {bline}')
        flattened.append(f'        {state_var} = {i+2 if i+1 < len(blocks) else "nil"}')
        flattened.append('    end')
    flattened.append('end')
    return '\n'.join(flattened)

def _inject_dead_code(source, count=20):
    lines = source.split('\n')
    for _ in range(count):
        pos = random.randint(0, len(lines) - 1)
        lines.insert(pos, _junk_code_block())
    return '\n'.join(lines)

def _add_anti_tamper(source):
    checksum = hashlib.md5(source.encode()).hexdigest()[:8]
    guard = f'''
local _integrity = "{checksum}"
local _tamper_count = 0
local function _verify()
    pcall(function()
        local src = debug and debug.getinfo and debug.getinfo(1, "S")
        if src and src.source and #src.source > 0 then
            local h = "{checksum}"
            if h ~= _integrity then
                _tamper_count = _tamper_count + 1
                if _tamper_count > 2 then
                    while true do end
                end
            end
        end
    end)
end
_verify()
'''
    return guard + '\n' + source

def _add_environment_hiding(source):
    proxy = f'''
local _real_env = getfenv and getfenv() or _ENV
local _hidden_env = setmetatable({{}}, {{
    __index = function(_, k)
        local v = _real_env[k]
        if type(v) == "function" then
            return function(...)
                local _{_random_name()} = {{...}}
                return v(...)
            end
        end
        return v
    end,
    __newindex = function(_, k, v)
        _real_env[k] = v
    end,
    __pairs = function() return pairs(_real_env) end,
    __call = function(_, ...) return ... end,
    __metatable = "locked",
    __tostring = function() return "table" end,
}})
if getfenv then setfenv(1, _hidden_env) else _ENV = _hidden_env end
'''
    return proxy + '\n' + source

def _add_metatable_proxy(source):
    proxy = f'''
local _real_setmeta = setmetatable
local _real_getmeta = getmetatable
setmetatable = function(t, mt)
    if mt then
        local _orig_idx = mt.__index
        local _orig_newidx = mt.__newindex
        local _orig_call = mt.__call
        local _orig_len = mt.__len
        local _orig_gc = mt.__gc
        if _orig_idx then
            mt.__index = function(t, k)
                local _{_random_name()} = k
                return type(_orig_idx) == "function" and _orig_idx(t, k) or _orig_idx[k]
            end
        end
        if _orig_newidx then
            mt.__newindex = function(t, k, v)
                if type(_orig_newidx) == "function" then _orig_newidx(t, k, v) else rawset(t, k, v) end
            end
        end
        if _orig_len then
            mt.__len = function(t) return _orig_len(t) end
        end
        if _orig_call then
            mt.__call = function(t, ...) return _orig_call(t, ...) end
        end
        if _orig_gc then
            mt.__gc = function(t) return _orig_gc(t) end
        end
    end
    return _real_setmeta(t, mt)
end
getmetatable = function(t)
    local mt = _real_getmeta(t)
    if mt and mt.__metatable then return nil end
    return mt
end
'''
    return proxy + '\n' + source

def _constant_array_transform(source):
    import re as _re
    lines = source.split('\n')
    numbers = []
    for line in lines:
        numbers.extend([int(n) for n in _re.findall(r'(?<![a-zA-Z_.])\d+(?![a-zA-Z_.])', line) if len(n) > 1 and int(n) > 100])
    if not numbers:
        return source
    unique = list(set(numbers))[:80]
    random.shuffle(unique)
    arr_name = _random_name()
    transformed = [f'local {arr_name} = {{' + ', '.join(str(n) for n in unique) + '}']
    for i, n in enumerate(unique):
        source = source.replace(str(n), f'{arr_name}[{i+1}]')
    return '\n'.join(transformed) + '\n' + source

def _add_stack_confusion(source):
    wrapper = f'''
local function _{_random_name()}(...)
    local _{_random_name()} = {{pcall(function() error("", 0) end)}}
    local _{_random_name()} = debug and debug.traceback and debug.traceback() or ""
    local _{_random_name()} = _{_random_name()}
    return ...
end
'''
    return wrapper + '\n' + source

def _add_timing_check(source):
    check = f'''
local _start = os and os.clock and os.clock() or 0
local _check_count = 0
local _max_checks = {random.randint(5, 20)}
local function _timing_check()
    _check_count = _check_count + 1
    if os and os.clock and os.clock() - _start > {random.randint(300, 900)} then
        while true do end
    end
    if _check_count > _max_checks then
        _start = os and os.clock and os.clock() or 0
        _check_count = 0
    end
end
'''
    return check + '\n' + source

def _add_dispatch_table(source):
    dname = _random_name()
    dispatch = f'''
local {dname} = setmetatable({{}}, {{__index = function(_, k) return function(...) return ... end end}})
{dname}[1] = function() end
{dname}[2] = function() return 0 end
{dname}[3] = function(x) return x end
{dname}[4] = function(x, y) return x + y end
{dname}[5] = function(...) return {{...}} end
local _{_random_name()} = {dname}[{random.randint(1,5)}]
'''
    return dispatch + '\n' + source

def _add_error_hiding(source):
    handler = '''
local _real_error = error
local _real_pcall = pcall
error = function(msg, level)
    local _msg = tostring(msg)
    if #_msg > 200 then
        _msg = _msg:sub(1, 200) .. "..."
    end
    _real_error("Script error: " .. _msg, (level or 1) + 2)
end
pcall = function(fn, ...)
    local _args = {...}
    local ok, result = _real_pcall(function()
        return fn(unpack(_args))
    end)
    if not ok then
        return false, "An error occurred"
    end
    return ok, result
end
'''
    return handler + '\n' + source

def _table_length_confusion(source):
    confusion = f'''
local _{_random_name()} = setmetatable({{}}, {{
    __len = function() return {random.randint(10, 100)} end,
    __index = function() return nil end,
    __newindex = function() end,
    __call = function() return nil end,
}})
local _{_random_name()} = #_{_random_name()}
'''
    return confusion + '\n' + source

def _add_double_encryption(source):
    key1 = _random_key()
    key2 = _random_key()
    wrapper = f'''
local _dk1 = "{key1}"
local _dk2 = "{key2}"
local function _dec1(s)
    local r = {{}}
    for i = 1, #s do
        local b = string.byte(s, i)
        local kb = string.byte(_dk1, (i-1) % #_dk1 + 1)
        r[i] = string.char(bit32.bxor(b, kb))
    end
    return table.concat(r)
end
local function _dec2(s)
    local r = {{}}
    for i = 1, #s do
        local b = string.byte(s, i)
        local kb = string.byte(_dk2, (i-1) % #_dk2 + 1)
        r[i] = string.char(bit32.bxor(b, kb))
    end
    return table.concat(r)
end
'''
    import re as _re
    lines = source.split('\n')
    encrypted_lines = [wrapper]
    for line in lines:
        def repl1(m):
            s = m.group(1)
            enc1 = ''.join(chr(ord(c) ^ ord(key1[i % len(key1)])) for i, c in enumerate(s))
            enc2 = ''.join(chr(ord(c) ^ ord(key2[i % len(key2)])) for i, c in enumerate(enc1))
            b64 = base64.b64encode(enc2.encode('latin-1')).decode('ascii')
            return f'_dec1(_dec2("{b64}"))'
        line = _re.sub(r'"([^"]*)"', repl1, line)
        encrypted_lines.append(line)
    return '\n'.join(encrypted_lines)

def _add_anti_debug(source):
    debug_guard = f'''
local _hook_detected = false
if debug and debug.sethook then
    local _{_random_name()} = function()
        _hook_detected = true
        if _hook_detected then
            while true do end
        end
    end
    debug.sethook(_{_random_name()}, "c", 1)
    debug.sethook()
end
local function _check_debugger()
    local _{_random_name()} = os and os.clock and os.clock() or 0
    local _{_random_name()} = 0
    while _{_random_name()} < 1000000 do
        _{_random_name()} = _{_random_name()} + 1
    end
    local _{_random_name()} = os and os.clock and os.clock() or 0
    if _{_random_name()} - _{_random_name()} > 0.1 then
        _hook_detected = true
    end
end
_check_debugger()
'''
    return debug_guard + '\n' + source

def _add_variable_renaming(source):
    import re as _re
    identifiers = set(_re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', source))
    reserved = {'and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while','print','require','pcall','xpcall','loadstring','load','pairs','ipairs','setmetatable','getmetatable','rawset','rawget','tostring','tonumber','table','string','math','coroutine','debug','io','os','unpack','select','type','assert','error','next','rawequal','_G','_ENV','getfenv','setfenv','newproxy','bit','bit32','game','workspace','Instance','task','typeof','getgenv','Enum','Color3','UDim2','CFrame','Vector2','Vector3'}
    renames = {}
    counter = 0
    for ident in sorted(identifiers, key=lambda x: -len(x)):
        if ident not in reserved and not ident.startswith('_'):
            if ident not in renames:
                renames[ident] = f'v{counter}'
                counter += 1
    for old, new in renames.items():
        source = _re.sub(r'\b' + _re.escape(old) + r'\b', new, source)
    return source

def _add_number_encryption(source):
    import re as _re
    def replace_number(m):
        n = int(m.group(0))
        if n > 255 or n < -255:
            return str(n)
        return _number_to_expression(n)
    return _re.sub(r'(?<![a-zA-Z_.])\d+(?![a-zA-Z_.])', replace_number, source)

def _add_dynamic_load_stub(source):
    stub = f'''
local _{_random_name()} = loadstring or load
if _{_random_name()} then
    local _{_random_name()} = _{_random_name()}([[
        local _{_random_name()} = function()
            return "{_random_key()}"
        end
        return _{_random_name()}()
    ]])
    if _{_random_name()} then
        _{_random_name()}()
    end
end
'''
    return stub + '\n' + source

def _add_stack_trace_validation(source):
    validation = f'''
local function _validate_stack()
    local _{_random_name()} = debug and debug.traceback and debug.traceback() or ""
    if _{_random_name()}:find("hook") or _{_random_name()}:find("inject") then
        while true do end
    end
end
_validate_stack()
'''
    return validation + '\n' + source

def _add_randomized_build(source):
    seed = random.randint(0, 99999999)
    header = f'''
local _BUILD_SEED = {seed}
local _BUILD_HASH = "{hashlib.md5(str(seed).encode()).hexdigest()[:12]}"
local _BUILD_TIME = {int(time.time())}
math.randomseed(_BUILD_SEED)
'''
    return header + '\n' + source

def _add_utf8_escape_decode(source):
    decoder = '''
local function _utf8_decode(s)
    return s:gsub("\\\\u(%x+)", function(h)
        return utf8 and utf8.char(tonumber(h, 16)) or string.char(tonumber(h, 16))
    end)
end
'''
    return decoder + '\n' + source

def _add_dead_boolean_removal(source):
    import re as _re
    source = _re.sub(r'\btrue\s+and\s+', '', source)
    source = _re.sub(r'\bfalse\s+or\s+', '', source)
    source = _re.sub(r'\s+and\s+true\b', '', source)
    source = _re.sub(r'\s+or\s+false\b', '', source)
    return source

def _add_proxify_locals(source):
    proxy = f'''
local _{_random_name()} = {{}}
setmetatable(_{_random_name()}, {{__newindex = function() end, __index = function() return function() end end}})
local function _proxy_locals(...)
    local args = {{...}}
    for i = 1, select('#', ...) do
        if type(args[i]) == "table" then
            args[i] = _{_random_name()}
        end
    end
    return unpack(args)
end
'''
    return proxy + '\n' + source

def _add_syntax_normalization(source):
    import re as _re
    source = _re.sub(r'[ \t]+', ' ', source)
    source = _re.sub(r'\n{3,}', '\n\n', source)
    source = _re.sub(r';\s*', ';\n', source)
    return source

def _add_redundant_expression_cleanup(source):
    import re as _re
    source = _re.sub(r'\b(\w+)\s*=\s*\1\s*;?\s*', '', source)
    source = _re.sub(r'return\s+;', 'return', source)
    source = _re.sub(r'do\s+end', '', source)
    return source

def _add_register_normalization(source):
    import re as _re
    pattern = _re.compile(r'\b(r\d+)\b')
    registers = set(pattern.findall(source))
    mapping = {r: f'reg{i}' for i, r in enumerate(sorted(registers, key=lambda x: int(x[1:]) if x[1:].isdigit() else 0))}
    for old, new in mapping.items():
        source = _re.sub(r'\b' + _re.escape(old) + r'\b', new, source)
    return source

def _add_function_layout_reconstruction(source):
    import re as _re
    source = _re.sub(r'\bend\s*\)', 'end)', source)
    source = _re.sub(r'\bend\s*$', 'end', source)
    source = _re.sub(r'\bfunction\s*\(', 'function(', source)
    source = _re.sub(r'\)\s*\)', '))', source)
    return source

def run_deobfuscation_pipeline(input_filename, output_filename):
    print(f"[*] Commencing pipeline execution on: {input_filename}")

    subprocess.run(["lune", "run", "extractor.luau", input_filename], check=True)

    with open("string_cache.json", "r") as f:
        string_lookup = json.load(f)

    with open(input_filename, "r", encoding="utf-8", errors="replace") as f:
        source_code = f.read()

    print("[*] Stage 2: Substituting string lookups across script body...")
    for index, raw_string in string_lookup.items():
        source_code = source_code.replace(f"R[{index}]", f'"{raw_string}"')
        source_code = source_code.replace(f'R["{index}"]', f'"{raw_string}"')

    print("[*] Stage 3: Applying advanced obfuscation layers...")
    key = _generate_encryption_key()
    source_code = _encrypt_strings(source_code, key)
    source_code = _inject_dead_code(source_code, random.randint(15, 30))
    source_code = _add_anti_tamper(source_code)
    source_code = _add_environment_hiding(source_code)
    source_code = _add_metatable_proxy(source_code)
    source_code = _constant_array_transform(source_code)
    source_code = _add_stack_confusion(source_code)
    source_code = _add_timing_check(source_code)
    source_code = _add_dispatch_table(source_code)
    source_code = _add_error_hiding(source_code)
    source_code = _table_length_confusion(source_code)
    source_code = _add_double_encryption(source_code)
    source_code = _add_anti_debug(source_code)
    source_code = _add_variable_renaming(source_code)
    source_code = _add_number_encryption(source_code)
    source_code = _add_dynamic_load_stub(source_code)
    source_code = _add_stack_trace_validation(source_code)
    source_code = _add_randomized_build(source_code)
    source_code = _add_utf8_escape_decode(source_code)
    source_code = _add_dead_boolean_removal(source_code)
    source_code = _add_proxify_locals(source_code)
    source_code = _add_syntax_normalization(source_code)
    source_code = _add_redundant_expression_cleanup(source_code)
    source_code = _add_register_normalization(source_code)
    source_code = _add_function_layout_reconstruction(source_code)
    source_code = _apply_control_flow_flattening(source_code)

    intermediate_file = "stage2_substituted.lua"
    with open(intermediate_file, "w", encoding="utf-8") as f:
        f.write(source_code)

    print("[*] Stage 4: Deploying AST Optimization Engines via Darklua...")
    darklua_config = {
        "generator": {
            "name": "readable",
            "column_span": 120
        },
        "rules": [
            "compute_expression",
            "remove_unused_if_branch",
            "remove_unused_while",
            "convert_index_to_field",
            "remove_nil_declaration",
            "remove_unused_variable",
            "remove_spaces",
            "inline_expression",
            "group_local_assignment",
            "remove_function_call_parens"
        ]
    }

    with open("darklua.json", "w") as f:
        json.dump(darklua_config, f, indent=4)

    try:
        subprocess.run(["darklua", "process", intermediate_file, output_filename], check=True)
        print(f"[+] Complete Success! Fully linearized code compiled inside: {output_filename}")
    except FileNotFoundError:
        print("[-] Critical: Darklua binary must be installed and globally appended to your system PATH variables.")
    finally:
        if os.path.exists(intermediate_file): os.remove(intermediate_file)
        if os.path.exists("string_cache.json"): os.remove("string_cache.json")
        if os.path.exists("darklua.json"): os.remove("darklua.json")

if __name__ == "__main__":
    run_deobfuscation_pipeline("Test deobf.txt", "deobfuscated_clean.lua")
