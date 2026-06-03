local fs = require("@lune/fs")
local process = require("@lune/process")

local targetFile = process.args[1]
local outFile = process.args[2] or "deobfuscated.lua"

if not fs.isFile(targetFile) then
    error("Target file not found: " .. targetFile)
end

local input = fs.readFile(targetFile)

local decoded_strings = {}
local getter_name = nil
local getter_offset = 0
local alpha = {}

local function safe_eval(expr)
    expr = expr:gsub("%s+", "")
    expr = expr:gsub("%-%(", "+("):gsub("%+%+", "+")
    expr = expr:gsub("%-%+", "-"):gsub("%+%-", "-")
    local tokens = {}
    for token in expr:gmatch("[%+%-]?%d+") do
        table.insert(tokens, tonumber(token))
    end
    local sum = 0
    for _, t in ipairs(tokens) do
        sum = sum + t
    end
    return sum
end

local function resolve_getter(n)
    local idx = n + getter_offset
    if idx >= 1 and idx <= #decoded_strings then
        local s = decoded_strings[idx]
        if s then
            return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
        end
    end
    return nil
end

local function decode_octal(s)
    return (s:gsub('\\(%d%d?%d?)', function(d)
        return string.char(tonumber(d, 8))
    end))
end

local function decode_base64(s, alpha_str)
    if not alpha_str or #alpha_str ~= 64 then
        return s
    end

    local rev = {}
    for i = 1, #alpha_str do
        rev[alpha_str:sub(i, i)] = i - 1
    end

    local bits = 0
    local bit_count = 0
    local out = {}

    for i = 1, #s do
        local c = s:sub(i, i)
        if c == '=' then break end
        local v = rev[c]
        if v then
            bits = (bits << 6) | v
            bit_count = bit_count + 6
            if bit_count >= 8 then
                bit_count = bit_count - 8
                table.insert(out, string.char((bits >> bit_count) & 0xFF))
            end
        end
    end

    return table.concat(out)
end

local alpha_match = input:match('["\']([A-Za-z0-9+/]{64})["\']')
if alpha_match then
    alpha_str = alpha_match
    for i = 1, #alpha_str do
        alpha[alpha_str:sub(i, i)] = i - 1
    end
end

local single_line = input:gsub("\n", " "):gsub("\r", " ")

local r_start = single_line:find('local%s+R%s*=%s*%{')
if r_start then
    local depth = 0
    local in_string = false
    local escape = false
    local end_pos = r_start
    for i = r_start, #single_line do
        local c = single_line:sub(i, i)
        if escape then
            escape = false
        elseif c == '\\' then
            escape = true
        elseif c == '"' then
            in_string = not in_string
        elseif not in_string then
            if c == '{' then
                depth = depth + 1
            elseif c == '}' then
                depth = depth - 1
                if depth == 0 then
                    end_pos = i
                    break
                end
            end
        end
    end
    local r_body = single_line:sub(r_start, end_pos)
    
    local raw_strings = {}
    for s in r_body:gmatch('"((?:[^"\\]|\\.)*)"') do
        local decoded = decode_octal(s)
        table.insert(raw_strings, decoded)
    end

    if #raw_strings > 0 then
        if alpha_str then
            for i, s in ipairs(raw_strings) do
                local decoded = decode_base64(s, alpha_str)
                if decoded and #decoded > 0 and decoded ~= s then
                    raw_strings[i] = decoded
                end
            end
        end

        local shuffle_match = single_line:match('ipairs%s*%(%s*%{([^}]+)%}%s*%)')
        local shuffle_pairs = {}
        if shuffle_match then
            for a, b in shuffle_match:gmatch('%{([%d]+)[,;]([%d]+)%}') do
                table.insert(shuffle_pairs, {tonumber(a), tonumber(b)})
            end
        end

        for _, pair in ipairs(shuffle_pairs) do
            local lo, hi = pair[1] - 1, pair[2] - 1
            while lo < hi and lo >= 1 and hi <= #raw_strings do
                raw_strings[lo], raw_strings[hi] = raw_strings[hi], raw_strings[lo]
                lo = lo + 1
                hi = hi - 1
            end
        end

        for _, s in ipairs(raw_strings) do
            if s and #s > 0 then
                table.insert(decoded_strings, s)
            end
        end
    end
end

local getter_patterns = {
    'local%s+function%s+(%w+)%s*%(%s*%1%s*%)%s*return%s+R%s*%[%s*%1%s*%+%s*%(([^)]+)%)%s*%]',
    'local%s+function%s+(%w+)%s*%(%s*%1%s*%)%s*return%s+R%s*%[%s*%1%s*%+%s*([%d%-%+]+)%s*%]',
}

for _, pattern in ipairs(getter_patterns) do
    local name, offset_str = single_line:match(pattern)
    if name and offset_str then
        getter_name = name
        getter_offset = safe_eval(offset_str)
        break
    end
end

local result = input

if getter_name and getter_offset then
    result = result:gsub(getter_name .. '%s*%(%s*([^)]+)%s*%)', function(expr)
        local n = safe_eval(expr)
        local s = resolve_getter(n)
        if s then
            return s
        end
        return getter_name .. "(" .. expr .. ")"
    end)
end

for i, s in ipairs(decoded_strings) do
    local escaped = s:gsub('\\', '\\\\'):gsub('"', '\\"')
    result = result:gsub('R%[' .. i .. '%]', '"' .. escaped .. '"')
    result = result:gsub('R%[ ' .. i .. ' %]', '"' .. escaped .. '"')
    result = result:gsub('R%["' .. i .. '"%]', '"' .. escaped .. '"')
end

local output = "-- Symbolically Evaluated Output\n"
output = output .. "-- " .. #decoded_strings .. " strings decoded\n"
if getter_name then
    output = output .. "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")\n"
    output = output .. "-- Replaced all " .. getter_name .. "() calls with string values\n"
end
output = output .. "\n"
output = output .. "local R = {\n"
for i, s in ipairs(decoded_strings) do
    local display = s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r')
    output = output .. '\t[' .. i .. '] = "' .. display .. '",\n'
end
output = output .. "}\n\n"
output = output .. result

fs.writeFile(outFile, output)
