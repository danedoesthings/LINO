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

local vm_var = nil
local pc_var = nil
local stack_var = nil
local reg_var = nil
local alloc_func = nil
local states = {}
local entry_state = nil

local while_start = input:find('while%s+(%w+)%s+do')
if while_start then
    vm_var = input:match('while%s+(%w+)%s+do', while_start)
end

local block_match = input:match('local%s+function%s*%([^)]*%)%s*([%w_,%s]*)%s*while%s+')
if block_match then
    local locals = block_match
    for var in locals:gmatch('(%w+)') do
        if var ~= vm_var then
            if not pc_var then pc_var = var
            elseif not stack_var then stack_var = var
            elseif not reg_var then reg_var = var end
        end
    end
end

local output_lines = {}
table.insert(output_lines, "-- Symbolic VM Execution Output")
table.insert(output_lines, "-- " .. #decoded_strings .. " strings decoded")
table.insert(output_lines, "-- VM variable: " .. (vm_var or "unknown"))
table.insert(output_lines, "")

local function extract_states(code, var_name)
    local st = {}
    local pos = 1
    local depth = 0
    local current_state = nil
    local current_body = {}
    local in_state = false
    
    while pos <= #code do
        local rest = code:sub(pos)
        local if_match = rest:match('^%s*if%s+' .. var_name .. '%s*<%s*(-?%d+)%s+then')
        local assign_match = rest:match('^%s*' .. var_name .. '%s*=%s*(-?%d+)')
        local end_match = rest:match('^%s*end%s*')
        
        if if_match and not in_state then
            in_state = true
            current_state = tonumber(if_match)
            current_body = {}
            pos = pos + #rest:match('^%s*if%s+' .. var_name .. '%s*<%s*(-?%d+)%s+then') + 4
        elseif assign_match and in_state then
            local next_state = tonumber(assign_match)
            local body_code = table.concat(current_body, "\n")
            body_code = resolve_getter_calls(body_code)
            st[current_state] = {
                body = body_code,
                next_state = next_state,
            }
            in_state = false
            current_state = nil
            current_body = {}
            pos = pos + #rest:match('^%s*' .. var_name .. '%s*=%s*(-?%d+)')
        else
            if in_state then
                local line = rest:match('^([^\n]*)')
                if line then
                    table.insert(current_body, line)
                    pos = pos + #line + 1
                else
                    pos = pos + 1
                end
            else
                pos = pos + 1
            end
        end
    end
    return st
end

if vm_var then
    local vm_code = input:match('while%s+' .. vm_var .. '%s+do%s*(.-)%s*end%s*$')
    if vm_code then
        states = extract_states(vm_code, vm_var)
    end
    
    if not states or #states == 0 then
        vm_code = input:match('while%s+' .. vm_var .. '%s+do(.-)end')
        if vm_code then
            states = extract_states(vm_code, vm_var)
        end
    end
end

table.insert(output_lines, "-- Found " .. #states .. " state transitions")
table.insert(output_lines, "")

local visited = {}
local execution_order = {}

local function find_entry_state()
    if not vm_var then return end
    local before_while = input:match('(.-)while%s+' .. vm_var .. '%s+do')
    if before_while then
        local assigns = {}
        for state in before_while:gmatch(vm_var .. '%s*=%s*(-?%d+)') do
            table.insert(assigns, tonumber(state))
        end
        if #assigns > 0 then
            entry_state = assigns[#assigns]
        end
    end
end

find_entry_state()

if entry_state and states then
    table.insert(output_lines, "-- Entry state: " .. tostring(entry_state))
    table.insert(output_lines, "")
    
    local current = entry_state
    local depth = 0
    
    while current and not visited[current] and depth < 500 do
        visited[current] = true
        depth = depth + 1
        local info = states[current]
        if info then
            table.insert(output_lines, "-- State " .. tostring(current) .. ":")
            if info.body and #info.body > 0 then
                table.insert(output_lines, info.body)
            else
                table.insert(output_lines, "--   (empty handler)")
            end
            table.insert(output_lines, "--   -> next state: " .. tostring(info.next_state))
            table.insert(output_lines, "")
            current = info.next_state
        else
            table.insert(output_lines, "-- State " .. tostring(current) .. ": NOT FOUND")
            break
        end
    end
else
    table.insert(output_lines, "-- Could not determine VM execution flow")
    table.insert(output_lines, "-- VM variable: " .. (vm_var or "not found"))
    table.insert(output_lines, "-- Entry state: " .. (tostring(entry_state) or "not found"))
    table.insert(output_lines, "-- States found: " .. tostring(#states))
end

local output = table.concat(output_lines, "\n")
fs.writeFile(outFile, output)
