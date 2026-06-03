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

local r_table_match = input:match('local%s+R%s*=%s*%{([^}]*)%}')
if r_table_match then
    local raw_strings = {}
    for s in r_table_match:gmatch('"((?:[^"\\]|\\.)*)"') do
        table.insert(raw_strings, s:gsub('\\(%d+)', function(d) return string.char(tonumber(d)) end))
    end

    local shuffle_match = input:match('ipairs%s*%(%s*%{([^}]+)%}%s*%)')
    local shuffle_pairs = {}
    if shuffle_match then
        for a, b in shuffle_match:gmatch('%{([%d]+)[,;]([%d]+)%}') do
            table.insert(shuffle_pairs, {tonumber(a), tonumber(b)})
        end
    end

    for _, pair in ipairs(shuffle_pairs) do
        local lo, hi = pair[1] - 1, pair[2] - 1
        while lo < hi do
            raw_strings[lo + 1], raw_strings[hi + 1] = raw_strings[hi + 1], raw_strings[lo + 1]
            lo = lo + 1
            hi = hi - 1
        end
    end

    for _, s in ipairs(raw_strings) do
        table.insert(decoded_strings, s)
    end
end

local getter_match = input:match('local%s+function%s+(%w+)%s*%(%s*%1%s*%)%s*return%s+R%s*%[%s*%1%s*%+%s*%(([^)]+)%)%s*%]')
if getter_match then
    getter_name = getter_match[1]
    getter_offset = safe_eval(getter_match[2])
end

local result = input

if getter_name then
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
    result = result:gsub('R%[' .. i .. '%]', '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"')
    result = result:gsub('R%[ ' .. i .. ' %]', '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"')
end

local output = "-- Symbolically Evaluated Output\n"
output = output .. "-- " .. #decoded_strings .. " strings decoded\n"
if getter_name then
    output = output .. "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")\n"
end
output = output .. "\n" .. result

fs.writeFile(outFile, output)
