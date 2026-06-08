--[[
Unveilr Stub - WeAreDevs deobfuscator
This is a simplified version that attempts to decode WeAreDevs obfuscation.
--]]

local args = {...}
local input_file = args[1]
local output_file = args[2]

if not input_file or not output_file then
    io.stderr:write("Usage: lune run main.lua input.lua output.lua\n")
    os.exit(1)
end

local file = io.open(input_file, "r")
if not file then
    io.stderr:write("Cannot open input file: " .. input_file .. "\n")
    os.exit(1)
end

local source = file:read("*a")
file:close()

-- Simple WeAreDevs decoder: look for string tables and decode
local function extract_strings(src)
    local patterns = {
        'local%s+EncStr%s*=%s*\{([^}]+)\}',
        'local%s+R%s*=%s*\{([^}]+)\}',
    }
    for _, pattern in ipairs(patterns) do
        local start_pos, end_pos = src:find(pattern)
        if start_pos then
            local body = src:sub(start_pos, end_pos)
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

local function decode_unicode(s)
    return (s:gsub('\\u([0-9a-fA-F]{4})', function(hex)
        local code = tonumber(hex, 16)
        if code and code <= 0x10FFFF then
            return string.char(code)
        end
        return '\\u' .. hex
    end))
end

local function extract_alphabet(src)
    local patterns = {
        'local%s+N%s*=%s*\{([^}]+)\}',
        'local%s+alphaMap%s*=%s*\{([^}]+)\}',
    }
    for _, pattern in ipairs(patterns) do
        local start_pos, end_pos = src:find(pattern)
        if start_pos then
            local body = src:sub(start_pos, end_pos)
            local chars = {}
            for char, idx in body:gmatch('"([A-Za-z0-9+/?])"%s*=%s*(%d+)') do
                local v = tonumber(idx)
                if v and v >= 0 and v <= 63 then
                    chars[v + 1] = char
                end
            end
            if #chars > 0 then
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

    for i = 1, #s do
        local c = s:sub(i, i)
        if c ~= '=' and not rev[c] then
            return nil
        end
    end

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
            local c1 = b64:sub(i, i)
            local c2 = b64:sub(i + 1, i + 1)
            local c3 = b64:sub(i + 2, i + 2)
            local c4 = b64:sub(i + 3, i + 3)

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

-- Main deobfuscation
local strings = extract_strings(source)
local result = source

if strings then
    local alphabet = extract_alphabet(source)
    local decoded = {}

    for _, s in ipairs(strings) do
        s = decode_unicode(s)
        s = decode_octal(s)

        if alphabet and #s >= 4 then
            local dec = custom_b64_decode(s, alphabet)
            if dec and is_lua_source(dec) then
                decoded[#decoded + 1] = dec
            else
                decoded[#decoded + 1] = s
            end
        else
            decoded[#decoded + 1] = s
        end
    end

    for _, s in ipairs(decoded) do
        if is_lua_source(s) then
            result = s
            break
        end
    end
end

local out = io.open(output_file, "w")
if out then
    out:write("-- Deobfuscated with Unveilr\n\n" .. result)
    out:close()
else
    io.stderr:write("Cannot write to output file: " .. output_file .. "\n")
    os.exit(1)
end

os.exit(0)
