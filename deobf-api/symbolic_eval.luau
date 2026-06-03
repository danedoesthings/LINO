local fs = require("@lune/fs")
local process = require("@lune/process")

local targetFile = process.args[1]
local outFile = process.args[2] or "deobfuscated.lua"
local stringsFile = process.args[3]

local input = fs.readFile(targetFile)

local decoded_strings = {}

if stringsFile and #stringsFile > 0 and fs.isFile(stringsFile) then
    local ok, serde = pcall(require, "@lune/serde")
    if ok and serde and serde.json then
        decoded_strings = serde.json.decode(fs.readFile(stringsFile))
    else
        local raw = fs.readFile(stringsFile)
        for s in raw:gmatch('"((?:[^"\\]|\\.)*)"') do
            table.insert(decoded_strings, s:gsub('\\"', '"'):gsub('\\\\', '\\'))
        end
    end
end

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

local single_line = input:gsub("\n", " "):gsub("\r", " ")

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

if getter_name and getter_offset and #decoded_strings > 0 then
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
output = output .. "-- " .. #decoded_strings .. " strings decoded (from Python)\n"
if getter_name then
    output = output .. "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")\n"
    output = output .. "-- Replaced all " .. getter_name .. "() calls with string values\n"
end
output = output .. "\n"
output = output .. result

fs.writeFile(outFile, output)
