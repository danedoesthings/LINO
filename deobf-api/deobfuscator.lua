local function decode_decimal(s)
    local result = {}
    local i = 1
    while i <= #s do
        if s:sub(i, i) == '\\' and i + 1 <= #s and s:sub(i + 1, i + 1):match('[0-9]') then
            local digits = ''
            local j = i + 1
            while j <= #s and #digits < 3 and s:sub(j, j):match('[0-9]') do
                digits = digits .. s:sub(j, j)
                j = j + 1
            end
            if #digits > 0 then
                local code = tonumber(digits)
                if code and code >= 0 and code <= 255 then
                    result[#result + 1] = string.char(code)
                    i = j
                else
                    result[#result + 1] = s:sub(i, i)
                    i = i + 1
                end
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

local function decode_unicode(s)
    return (s:gsub('\\u([0-9a-fA-F]{4})', function(hex)
        local code = tonumber(hex, 16)
        if code and code <= 0x10FFFF then
            return string.char(code)
        end
        return '\\u' .. hex
    end))
end

local function extract_strings(source)
    local patterns = {
        'local%s+EncStr%s*=%s*\{([^}]+)\}',
        'local%s+R%s*=%s*\{([^}]+)\}',
        'local%s+Y%s*=%s*\{([^}]+)\}',
        'local%s+S%s*=%s*\{([^}]+)\}',
        'EncStr%s*=%s*\{([^}]+)\}',
        'R%s*=%s*\{([^}]+)\}',
        'Y%s*=%s*\{([^}]+)\}',
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

local function extract_alphabet(source)
    local patterns = {
        'local%s+N%s*=%s*\{([^}]+)\}',
        'local%s+alphaMap%s*=%s*\{([^}]+)\}',
        'local%s+aMap%s*=%s*\{([^}]+)\}',
        'local%s+alphabet%s*=%s*\{([^}]+)\}',
        'N%s*=%s*\{([^}]+)\}',
        'alphaMap%s*=%s*\{([^}]+)\}',
    }
    for _, pattern in ipairs(patterns) do
        local start_pos, end_pos = source:find(pattern)
        if start_pos then
            local body = source:sub(start_pos, end_pos)
            local chars = {}
            -- Pattern: "char" = index
            for char, idx in body:gmatch('"([A-Za-z0-9+/?])"%s*=%s*(%d+)') do
                local v = tonumber(idx)
                if v and v >= 0 and v <= 63 then
                    chars[v + 1] = char
                end
            end
            -- Pattern: [index] = "char"
            for idx, char in body:gmatch('\[(%d+)%]%s*=%s*"([A-Za-z0-9+/?])"') do
                local v = tonumber(idx)
                if v and v >= 0 and v <= 63 then
                    chars[v + 1] = char
                end
            end
            -- Pattern: char = index (unquoted)
            for char, idx in body:gmatch('([A-Za-z0-9+/?])%s*=%s*(%d+)') do
                local v = tonumber(idx)
                if v and v >= 0 and v <= 63 and not chars[v + 1] then
                    chars[v + 1] = char
                end
            end
            -- === NEW: Pattern: ["\\ddd"] = index (decimal escapes) ===
            for escaped, idx in body:gmatch('"(\\%d+)"%s*=%s*([+-]?[%d()+%-*/]+)') do
                local code = tonumber(escaped:sub(2))
                if code and code >= 0 and code <= 255 then
                    local char = string.char(code)
                    local v = tonumber(idx)
                    if v and v >= 0 and v <= 63 then
                        chars[v + 1] = char
                    end
                end
            end
            if #chars > 0 then
                -- Fill in missing positions
                local std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                local used = {}
                for _, c in ipairs(chars) do
                    if c then used[c] = true end
                end
                for i = 1, 64 do
                    if not chars[i] then
                        for j = 1, #std do
                            local c = std:sub(j, j)
                            if not used[c] then
                                chars[i] = c
                                used[c] = true
                                break
                            end
                        end
                    end
                end
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
    -- Validate all characters
    for i = 1, #s do
        local c = s:sub(i, i)
        if c ~= '=' and not rev[c] then
            return nil
        end
    end
    -- Translate to standard base64
    local std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local rev_std = {}
    for i = 1, #std do
        rev_std[std:sub(i, i)] = i - 1
    end
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
    local result = {}
    for i = 1, #b64, 4 do
        if i + 3 <= #b64 then
            local c1, c2, c3, c4 = b64:sub(i, i), b64:sub(i + 1, i + 1), b64:sub(i + 2, i + 2), b64:sub(i + 3, i + 3)
            local v1 = c1 ~= '=' and rev_std[c1] or 0
            local v2 = c2 ~= '=' and rev_std[c2] or 0
            local v3 = c3 ~= '=' and rev_std[c3] or 0
            local v4 = c4 ~= '=' and rev_std[c4] or 0
            local combined = v1 * 262144 + v2 * 4096 + v3 * 64 + v4
            local b1 = math.floor(combined / 65536) % 256
            local b2 = math.floor(combined / 256) % 256
            local b3 = combined % 256
            result[#result + 1] = string.char(b1)
            if c3 ~= '=' then
                result[#result + 1] = string.char(b2)
            end
            if c4 ~= '=' then
                result[#result + 1] = string.char(b3)
            end
        end
    end
    return table.concat(result)
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

local function extract_shuffle_ops(source)
    local ops = {}
    local pattern = 'ipairs%s*\(\s*\{([^}]*)\}\s*\)'
    local start_pos, end_pos = source:find(pattern)
    if start_pos then
        local body = source:sub(start_pos, end_pos)
        for a, b in body:gmatch('\{(%d+),%s*(%d+)\}') do
            local x, y = tonumber(a), tonumber(b)
            if x and y and x < y then
                ops[#ops + 1] = {x, y}
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
        local lo, hi = a, b
        -- Reverse the range [lo, hi] (1-indexed, Lua-style swap)
        while lo < hi do
            result[lo], result[hi] = result[hi], result[lo]
            lo = lo + 1
            hi = hi - 1
        end
    end
    return result
end

local function deobfuscate(source)
    -- Extract strings
    local strings = extract_strings(source)
    if not strings then
        return nil, "No string table found"
    end

    -- Apply shuffle operations
    local ops = extract_shuffle_ops(source)
    if #ops > 0 then
        strings = apply_shuffle(strings, ops)
    end

    -- Extract alphabet
    local alphabet = extract_alphabet(source)

    -- Decode each string
    local decoded_strings = {}
    for _, s in ipairs(strings) do
        s = decode_unicode(s)
        s = decode_decimal(s)
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

    -- Find the first valid Lua source
    for _, s in ipairs(decoded_strings) do
        if is_lua_source(s) then
            return s, "success"
        end
    end

    -- Return the longest decoded string as fallback
    local best = nil
    local best_len = 0
    for _, s in ipairs(decoded_strings) do
        if #s > best_len then
            best = s
            best_len = #s
        end
    end
    if best and is_lua_source(best) then
        return best, "success"
    end

    return nil, "No valid Lua source found"
end

-- Main entry point
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
    io.stderr:write("Usage: lua deobfuscator.lua input.lua [-o output.lua]\n")
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
