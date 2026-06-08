local function decode_octal(s)
    local result = {}
    local i = 1
    while i <= #s do
        if s:sub(i, i) == '\\' and i + 1 <= #s then
            local octal = ''
            local j = i + 1
            while j <= #s and #octal < 3 and s:sub(j, j):match('[0-7]') do
                octal = octal .. s:sub(j, j)
                j = j + 1
            end
            if #octal > 0 then
                result[#result + 1] = string.char(tonumber(octal, 8))
                i = j
            else
                result[#result + 1] = s:sub(i, i)
                i = i + 1
            end
        else
            result[#result + 1] = s:sub(i, i)
            i = i + 1
        end
    end
    return table.concat(result)
end

local function decode_string(s)
    s = s:gsub('\\u([0-9a-fA-F]{4})', function(hex)
        return string.char(tonumber(hex, 16))
    end)
    s = decode_octal(s)
    return s
end

local function extract_alphabet(source)
    local patterns = {
        'local%s+N%s*=%s*{([^}]+)}',
        'local%s+alphaMap%s*=%s*{([^}]+)}',
    }
    for _, pattern in ipairs(patterns) do
        local start_pos, end_pos = source:find(pattern)
        if start_pos then
            local body = source:sub(start_pos, end_pos)
            local chars = {}
            for match in body:gmatch('"([A-Za-z0-9+/])"%s*=%s*(%d+)') do
                local char = match:match('"([^"]+)"')
                local idx = tonumber(match:match('=(%d+)'))
                if char and idx and #char == 1 and idx >= 0 and idx <= 63 then
                    chars[idx + 1] = char
                end
            end
            if #chars == 64 then
                return table.concat(chars)
            end
        end
    end
    return nil
end

local function custom_b64_decode(s, alphabet)
    if not alphabet or #alphabet ~= 64 then
        return nil
    end
    local rev = {}
    for i = 1, #alphabet do
        rev[alphabet:sub(i, i)] = i - 1
    end
    for i = 1, #s do
        if not rev[s:sub(i, i)] and s:sub(i, i) ~= '=' then
            return nil
        end
    end
    local std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local translated = {}
    for i = 1, #s do
        local c = s:sub(i, i)
        if c ~= '=' then
            translated[#translated + 1] = std:sub(rev[c] + 1, rev[c] + 1)
        else
            translated[#translated + 1] = '='
        end
    end
    local b64 = table.concat(translated)
    local padding = (4 - (#b64 % 4)) % 4
    if padding > 0 then
        b64 = b64 .. string.rep('=', padding)
    end
    return (b64:gsub('.', function(c)
        return string.char(tonumber(c, 16) or 0)
    end))
end

local function is_lua_source(s)
    if #s < 20 then
        return false
    end
    local keywords = {'function', 'local', 'return', 'print', 'if', 'then', 'else', 'end', 'while', 'for', 'do'}
    local count = 0
    for _, kw in ipairs(keywords) do
        if s:find(kw, 1, true) then
            count = count + 1
        end
    end
    return count >= 2
end

local function extract_strings(source)
    local patterns = {
        'local%s+EncStr%s*=%s*{([^}]+)}',
        'local%s+R%s*=%s*{([^}]+)}',
    }
    for _, pattern in ipairs(patterns) do
        local start_pos, end_pos = source:find(pattern)
        if start_pos then
            local body = source:sub(start_pos, end_pos)
            local strings = {}
            for match in body:gmatch('"(([^"\\]|\\.)*)"') do
                strings[#strings + 1] = match
            end
            if #strings > 0 then
                return strings
            end
        end
    end
    return nil
end

local function extract_shuffle_ops(source)
    local ops = {}
    local pattern = 'ipairs%s*%(%s*{([^}]+)}%s*%)'
    local start_pos, end_pos = source:find(pattern)
    if start_pos then
        local body = source:sub(start_pos, end_pos)
        for pair in body:gmatch('{(%d+),%s*(%d+)}') do
            local a = tonumber(pair:match('(%d+)'))
            local b = tonumber(pair:match('(%d+)'))
            if a and b then
                ops[#ops + 1] = {a, b}
            end
        end
    end
    return ops
end

local function apply_shuffle(strings, ops)
    local result = {}
    for i, v in ipairs(strings) do
        result[i] = v
    end
    for _, op in ipairs(ops) do
        local a, b = op[1], op[2]
        local lo, hi = a - 1, b - 1
        while lo < hi do
            result[lo], result[hi] = result[hi], result[lo]
            lo = lo + 1
            hi = hi - 1
        end
    end
    return result
end

local function deobfuscate(source)
    local strings = extract_strings(source)
    if not strings then
        return nil, "No string table found"
    end
    local ops = extract_shuffle_ops(source)
    if #ops > 0 then
        strings = apply_shuffle(strings, ops)
    end
    local alphabet = extract_alphabet(source)
    local decoded_strings = {}
    for _, s in ipairs(strings) do
        s = decode_string(s)
        if alphabet and #s >= 4 then
            local decoded = custom_b64_decode(s, alphabet)
            if decoded and is_lua_source(decoded) then
                decoded_strings[#decoded_strings + 1] = decoded
            else
                decoded_strings[#decoded_strings + 1] = s
            end
        else
            decoded_strings[#decoded_strings + 1] = s
        end
    end
    for _, s in ipairs(decoded_strings) do
        if is_lua_source(s) then
            return s, "success"
        end
    end
    return nil, "No valid Lua source found"
end

local args = {...}
local input_file = args[1]
local output_file = nil
for i = 1, #args do
    if args[i] == '-o' and i + 1 <= #args then
        output_file = args[i + 1]
        break
    end
end
if not input_file then
    io.stderr:write("Usage: lua vm_deobfuscator.lua input.lua [-o output.lua]\n")
    os.exit(1)
end
local file = io.open(input_file, "r")
if not file then
    io.stderr:write("Cannot open input file: " .. input_file .. "\n")
    os.exit(1)
end
local source = file:read("*a")
file:close()
local result, msg = deobfuscate(source)
if not result then
    io.stderr:write("Deobfuscation failed: " .. msg .. "\n")
    os.exit(1)
end
if output_file then
    local out = io.open(output_file, "w")
    if out then
        out:write("-- Deobfuscated with Prometheus Deobfuscator\n\n" .. result)
        out:close()
    else
        io.stderr:write("Cannot write to output file: " .. output_file .. "\n")
        os.exit(1)
    end
else
    print(result)
end
os.exit(0)
