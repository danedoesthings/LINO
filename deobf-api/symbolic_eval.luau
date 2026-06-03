local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

local targetFile = process.args[1]
local outFile = process.args[2] or "deobfuscated.lua"
local stringsFile = process.args[3]

local input = fs.readFile(targetFile)

local decoded_strings = {}

if stringsFile and #stringsFile > 0 and fs.isFile(stringsFile) then
    local chunk, err = luau.load(fs.readFile(stringsFile))
    if chunk then
        local success, result = pcall(chunk)
        if success and type(result) == "table" then
            for _, s in ipairs(result) do
                table.insert(decoded_strings, s)
            end
        end
    end
end

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

local single_line = input:gsub("\n", " "):gsub("\r", " ")

local getter_name = nil
local getter_offset = 0

local getter_patterns = {
    'local%s+function%s+(%w+)%s*%(%s*%w+%s*%)%s*return%s+R%s*%[%s*%w+%s*([+%-])%s*%(([^)]+)%)%s*%]',
    'local%s+function%s+(%w+)%s*%(%s*%w+%s*%)%s*return%s+R%s*%[%s*%w+%s*([+%-])%s*([%d%-%+]+)%s*%]',
}

for _, pattern in ipairs(getter_patterns) do
    local name, op, offset_str = single_line:match(pattern)
    if name and offset_str then
        getter_name = name
        local val = safe_eval(offset_str)
        if op == '-' then val = -val end
        getter_offset = val
        break
    end
end

local result = input

if getter_name and getter_offset and #decoded_strings > 0 then
    result = result:gsub('(?<![a-zA-Z0-9_])' .. getter_name .. '%s*%(%s*([^)]+)%s*%)', function(expr)
        local n = safe_eval(expr)
        if n then
            local idx = n + getter_offset
            if idx >= 1 and idx <= #decoded_strings then
                local s = decoded_strings[idx]
                if s then
                    return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
                end
            end
        end
        return getter_name .. "(" .. expr .. ")"
    end)
end

for i, s in ipairs(decoded_strings) do
    local escaped = s:gsub('\\', '\\\\'):gsub('"', '\\"')
    result = result:gsub('R%[' .. i .. '%]', '"' .. escaped .. '"')
    result = result:gsub('R%[ ' .. i .. ' %]', '"' .. escaped .. '"')
end

local output = "-- Deobfuscated Output\n"
output = output .. "-- " .. #decoded_strings .. " strings decoded\n"
if getter_name then
    output = output .. "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")\n"
    output = output .. "-- Replaced all " .. getter_name .. "() calls with string values\n"
end
output = output .. "\n"
output = output .. result

fs.writeFile(outFile, output)
