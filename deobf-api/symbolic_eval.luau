local fs = require("@lune/fs")
local process = require("@lune/process")

local targetFile = process.args[1]
local outFile = process.args[2] or "deobfuscated.lua"

if not fs.isFile(targetFile) then
    error("Target file not found: " .. targetFile)
end

local input = fs.readFile(targetFile)

local alpha = {}
local decoded_strings = {}
local getter_name = nil
local getter_offset = 0
local lines = {}
local index = 0

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

local function extract_alpha_and_strings(text)
    local alpha_match = text:match('local%s+(%w+)%s*=%s*%{([^}]+)%}')
    if not alpha_match then
        for m in text:gmatch('([A-Za-z0-9+/]{64})') do
            if #m == 64 then
                alpha = {}
                for j = 1, #m do
                    alpha[m:sub(j, j)] = j - 1
                end
                break
            end
        end
    else
        local body = alpha_match[2]
        local entries = {}
        for key, val in body:gmatch('([A-Za-z_])%s*=%s*([%d%+%-%*%(%)]+)') do
            local v = safe_eval(val)
            entries[v] = key
        end
        alpha = {}
        for i = 0, 63 do
            alpha[entries[i] or ''] = i
        end
    end

    local r_table_match = text:match('local%s+R%s*=%s*%{([^}]*)%}')
    if r_table_match then
        local raw_strings = {}
        for s in r_table_match:gmatch('"((?:[^"\\]|\\.)*)"') do
            table.insert(raw_strings, s:gsub('\\(%d+)', function(d) return string.char(tonumber(d)) end))
        end

        local shuffle_match = text:match('ipairs%s*%(%s*%{([^}]+)%}%s*%)')
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

    local getter_match = text:match('local%s+function%s+(%w+)%s*%(%s*%1%s*%)%s*return%s+R%s*%[%s*%1%s*%+%s*%(([^)]+)%)%s*%]')
    if getter_match then
        getter_name = getter_match[1]
        getter_offset = safe_eval(getter_match[2])
    end
end

for line in input:gmatch("[^\r\n]+") do
    index = index + 1
    lines[index] = line
end

extract_alpha_and_strings(input)

local vm_var = nil
local entry_state = nil
local states = {}

for i = 1, index do
    local line = lines[i]
    
    local while_match = line:match('while%s+(%w+)%s+do')
    if while_match and not vm_var then
        vm_var = while_match
    end
    
    local if_match = line:match('if%s+' .. (vm_var or '%w+') .. '%s*<%s*(-?%d+)%s+then')
    if if_match and vm_var then
        local pivot = tonumber(if_match)
        local body_lines = {}
        local depth = 1
        local j = i + 1
        while j <= index and depth > 0 do
            if lines[j]:match('^%s*if%s+') or lines[j]:match('^%s*for%s+') or lines[j]:match('^%s*while%s+') then
                depth = depth + 1
            elseif lines[j]:match('^%s*end%s*$') or lines[j]:match('^%s*end[;%s]') then
                depth = depth - 1
                if depth > 0 then
                    table.insert(body_lines, lines[j])
                end
            else
                table.insert(body_lines, lines[j])
            end
            j = j + 1
        end
    end
end

local output_lines = {}
table.insert(output_lines, "-- Symbolically Evaluated Output")
table.insert(output_lines, "-- " .. #decoded_strings .. " strings decoded")
table.insert(output_lines, "")

if getter_name then
    table.insert(output_lines, "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")")
    table.insert(output_lines, "")
end

table.insert(output_lines, "local R = {")
for i, s in ipairs(decoded_strings) do
    table.insert(output_lines, "\t[" .. i .. "] = \"" .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. "\",")
end
table.insert(output_lines, "}")
table.insert(output_lines, "")

if getter_name then
    local result = input
    local replaced = 0
    result = result:gsub(getter_name .. '%s*%(%s*([^)]+)%s*%)', function(expr)
        local n = safe_eval(expr)
        local s = resolve_getter(n)
        if s then
            replaced = replaced + 1
            return s
        end
        return getter_name .. "(" .. expr .. ")"
    end)
    
    if replaced > 0 then
        table.insert(output_lines, "-- Resolved " .. replaced .. " " .. getter_name .. "() calls")
        table.insert(output_lines, "")
    end
end

local output = table.concat(output_lines, "\n")
fs.writeFile(outFile, output)
