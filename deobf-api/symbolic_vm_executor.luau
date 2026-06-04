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

local function resolve_string(expr_str)
    local n = safe_eval(expr_str)
    if n then
        local idx = n + getter_offset
        if idx >= 1 and idx <= #decoded_strings then
            local s = decoded_strings[idx]
            if s then return s end
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

local function resolve_getter_calls(code)
    if not getter_name then return code end
    return code:gsub(getter_name .. '%s*%(%s*([^)]+)%s*%)', function(expr)
        local s = resolve_string(expr)
        if s then
            return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"'
        end
        return getter_name .. "(" .. expr .. ")"
    end)
end

local function classify_handler(code)
    if not code then return nil end
    
    local strings_found = {}
    for s in code:gmatch('"([^"]+)"') do
        table.insert(strings_found, s)
    end
    
    if code:find('I%[.-%]%s*=%s*"[^"]*"') then
        for reg, val in code:gmatch('I%[([^%]]+)%]%s*=%s*"([^"]*)"') do
            if val and #val > 0 then
                return 'LOADK  ' .. reg .. ' = "' .. val .. '"'
            end
        end
    end
    
    if code:find('I%[.-%]%s*=%s*.-%[.-%]') then
        for reg1, reg2 in code:gmatch('I%[([^%]]+)%]%s*=%s*I%[([^%]]+)%]') do
            return 'MOVE   ' .. reg1 .. ' = ' .. reg2
        end
    end
    
    if code:find('=%s*.-%s*%(') then
        for func, args in code:gmatch('=%s*(%w+)%s*%(([^)]*)%)') do
            return 'CLOSURE ' .. func .. '(' .. args .. ')'
        end
    end
    
    if strings_found and #strings_found > 0 then
        return 'STRINGS ' .. table.concat(strings_found, ', ')
    end
    
    return 'CALC   ' .. (code:sub(1, 80))
end

local function find_vm_loop(text)
    local vm_var = nil
    local loop_body = nil
    
    for var in text:gmatch('while%s+(%w+)%s+do') do
        vm_var = var
        break
    end
    
    if not vm_var then
        return nil, nil
    end
    
    local while_pos = text:find('while%s+' .. vm_var .. '%s+do')
    if while_pos then
        local depth = 1
        local pos = while_pos + #('while ' .. vm_var .. ' do')
        local end_pos = pos
        while pos <= #text and depth > 0 do
            local c = text:sub(pos, pos)
            if c == 'e' and text:sub(pos, pos+2) == 'end' then
                local before = text:sub(pos-1, pos-1)
                local after = text:sub(pos+3, pos+3)
                if (before == ' ' or before == '\n' or before == ';') and
                   (after == ' ' or after == '\n' or after == ';' or after == '' or pos+3 > #text) then
                    depth = depth - 1
                    if depth == 0 then
                        end_pos = pos + 2
                        break
                    end
                end
            elseif text:sub(pos, pos+4) == 'while' then
                depth = depth + 1
            elseif text:sub(pos, pos+1) == 'if' then
                depth = depth + 1
            elseif text:sub(pos, pos+1) == 'do' then
                depth = depth + 1
            end
            pos = pos + 1
        end
        loop_body = text:sub(while_pos, end_pos)
    end
    
    return vm_var, loop_body
end

local vm_var, loop_body = find_vm_loop(input)

local output_lines = {}
table.insert(output_lines, "-- Deobfuscated Output (Symbolic VM Execution)")
table.insert(output_lines, "-- " .. #decoded_strings .. " strings decoded")
if getter_name then
    table.insert(output_lines, "-- Getter: " .. getter_name .. "(N + " .. tostring(getter_offset) .. ")")
end
table.insert(output_lines, "")

if vm_var and loop_body then
    table.insert(output_lines, "-- VM State Machine Traced Execution")
    table.insert(output_lines, "-- Variable: " .. vm_var)
    table.insert(output_lines, "")
    
    local resolved_loop = resolve_getter_calls(loop_body)
    
    local states = {}
    local state_order = {}
    
    for state_num, body, next_state in resolved_loop:gmatch('if%s+' .. vm_var .. '%s*<%s*(-?%d+)%s+then%s*(.-)%s*' .. vm_var .. '%s*=%s*(-?%d+)') do
        local num = tonumber(state_num)
        local next = tonumber(next_state)
        if num and next then
            local handler = classify_handler(body)
            states[num] = {
                body = body:gsub('%s+', ' '):sub(1, 120),
                handler = handler or '(unknown)',
                next_state = next,
            }
            table.insert(state_order, num)
        end
    end
    
    table.sort(state_order)
    
    local entry = nil
    for _, s in ipairs(state_order) do
        if s > 0 and not entry then
            entry = s
            break
        end
    end
    
    if entry then
        local current = entry
        local visited = {}
        local depth = 0
        local max_depth = 100
        
        table.insert(output_lines, "-- Execution trace (entry: " .. tostring(entry) .. "):")
        table.insert(output_lines, "")
        
        while current and not visited[current] and depth < max_depth do
            visited[current] = true
            depth = depth + 1
            local info = states[current]
            if info then
                table.insert(output_lines, "[" .. current .. "] " .. info.handler)
                table.insert(output_lines, "    -> state " .. tostring(info.next_state))
                table.insert(output_lines, "")
                current = info.next_state
            else
                table.insert(output_lines, "[" .. current .. "] (unknown state)")
                break
            end
        end
        
        table.insert(output_lines, "-- Total states traced: " .. depth)
    end
    
    table.insert(output_lines, "")
    table.insert(output_lines, "-- Notable states (containing known strings):")
    table.insert(output_lines, "")
    
    local notable = {}
    for _, num in ipairs(state_order) do
        local info = states[num]
        if info then
            local body = info.body
            for s in body:gmatch('"([^"]+)"') do
                if s == 'print' or s == 'pcall' or s == 'tostring' or s == 'tonumber'
                    or s == 'error' or s == 'table' or s == 'concat' or s == 'math'
                    or s == 'floor' or s == 'char' or s == 'gsub' or s == 'byte'
                    or s == 'Tamper Detected!' then
                    if not notable[num] then
                        notable[num] = {}
                    end
                    table.insert(notable[num], s)
                end
            end
        end
    end
    
    for num, strings in pairs(notable) do
        table.insert(output_lines, "  State " .. tostring(num) .. ": " .. table.concat(strings, ", "))
    end
else
    table.insert(output_lines, "-- VM dispatcher not found in standard format")
    table.insert(output_lines, "-- Falling back to string-resolved output")
    table.insert(output_lines, "")
    
    local resolved = resolve_getter_calls(input)
    for i, s in ipairs(decoded_strings) do
        local escaped = s:gsub('\\', '\\\\'):gsub('"', '\\"')
        resolved = resolved:gsub('R%[' .. i .. '%]', '"' .. escaped .. '"')
    end
    table.insert(output_lines, resolved)
end

table.insert(output_lines, "")
table.insert(output_lines, "-- Decoded String Table:")
for i, s in ipairs(decoded_strings) do
    table.insert(output_lines, "  [" .. i .. '] = "' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '"')
end

local output = table.concat(output_lines, "\n")
fs.writeFile(outFile, output)
