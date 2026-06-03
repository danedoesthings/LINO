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

local function resolve_string(n)
    local idx = n + getter_offset
    if idx >= 1 and idx <= #decoded_strings then
        return decoded_strings[idx] or ("<nil_" .. idx .. ">")
    end
    return "<unknown_" .. n .. ">"
end

local vm_var = single_line:match('while%s+(%w+)%s+do')

local lines = {}
for line in input:gmatch("[^\r\n]+") do
    table.insert(lines, line)
end

local dispatch_start = 0
local dispatch_end = 0
local depth = 0
for i, line in ipairs(lines) do
    if line:match('^%s*while%s+' .. (vm_var or '') .. '%s+do') then
        dispatch_start = i
        depth = 1
    elseif dispatch_start > 0 then
        if line:match('^%s*if%s+') or line:match('^%s*for%s+') or line:match('^%s*while%s+') then
            depth = depth + 1
        elseif line:match('^%s*end%s*$') or line:match('^%s*end[;%s]') then
            depth = depth - 1
            if depth == 0 then
                dispatch_end = i
                break
            end
        end
    end
end

local output = {}
table.insert(output, "-- VM Executor Output")
table.insert(output, "-- " .. #decoded_strings .. " strings decoded")
if getter_name then
    table.insert(output, "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")")
end
table.insert(output, "")

local registers = {}
local instr_table = {}
local stack = {}
local state_count = 0

local dispatch_body = {}
if dispatch_start > 0 and dispatch_end > 0 then
    for i = dispatch_start + 1, dispatch_end - 1 do
        table.insert(dispatch_body, lines[i])
    end
end

local state_blocks = {}
local current_state = nil
local current_block = {}

for _, line in ipairs(dispatch_body) do
    local state_match = line:match(vm_var .. '%s*=%s*(-?%d+)')
    if state_match then
        if current_state then
            state_blocks[tonumber(current_state)] = table.concat(current_block, "\n")
        end
        current_state = state_match
        current_block = {}
    else
        table.insert(current_block, line)
    end
end
if current_state then
    state_blocks[tonumber(current_state)] = table.concat(current_block, "\n")
end

local visited = {}
local state_order = {}

local function extract_state(state_num)
    if visited[state_num] then return end
    visited[state_num] = true
    table.insert(state_order, state_num)

    local block = state_blocks[state_num]
    if not block then return end

    local next_states = {}
    for target in block:gmatch(vm_var .. '%s*=%s*(-?%d+)') do
        table.insert(next_states, tonumber(target))
    end

    for _, ns in ipairs(next_states) do
        extract_state(ns)
    end
end

if getter_name and getter_offset then
    for state_str, block in pairs(state_blocks) do
        local state_num = tonumber(state_str)
        if not visited[state_num] then
            extract_state(state_num)
        end
    end

    table.insert(output, "-- Execution trace (" .. #state_order .. " states)")
    table.insert(output, "")

    for _, state_num in ipairs(state_order) do
        local block = state_blocks[state_num]
        if block then
            local resolved = block

            resolved = resolved:gsub(getter_name .. '%s*%(%s*([^)]+)%s*%)', function(expr)
                local n = safe_eval(expr)
                local s = resolve_string(n)
                if s then
                    return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
                end
                return getter_name .. "(" .. expr .. ")"
            end)

            resolved = resolved:gsub('R%s*%[%s*([^%]]+)%s*%]', function(idx)
                local i = safe_eval(idx)
                if i and i >= 1 and i <= #decoded_strings then
                    local s = decoded_strings[i]
                    if s then
                        return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
                    end
                end
                return "R[" .. idx .. "]"
            end)

            table.insert(output, "-- State " .. state_num .. ":")
            for line in resolved:gmatch("[^\n]+") do
                table.insert(output, "--   " .. line)
            end
            table.insert(output, "")
        end
    end
end

table.insert(output, "-- All decoded strings:")
table.insert(output, "local R = {")
for i, s in ipairs(decoded_strings) do
    if s then
        table.insert(output, '\t[' .. i .. '] = "' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '",')
    end
end
table.insert(output, "}")
table.insert(output, "")
table.insert(output, input)

fs.writeFile(outFile, table.concat(output, "\n"))
