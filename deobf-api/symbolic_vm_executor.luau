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

local output_lines = {}
table.insert(output_lines, "-- Deobfuscated Output")
table.insert(output_lines, "-- " .. #decoded_strings .. " strings decoded")
table.insert(output_lines, "")

local resolved = resolve_getter_calls(input)

for i, s in ipairs(decoded_strings) do
    local escaped = s:gsub('\\', '\\\\'):gsub('"', '\\"')
    resolved = resolved:gsub('R%[' .. i .. '%]', '"' .. escaped .. '"')
    resolved = resolved:gsub('R%[ ' .. i .. ' %]', '"' .. escaped .. '"')
end

local function try_evaluate_expression(expr_str)
    local n = safe_eval(expr_str)
    if n then return tostring(n) end
    local s = resolve_string(expr_str)
    if s then return '"' .. s .. '"' end
    return expr_str
end

local payload_start = resolved:find('return%(function%(')
if payload_start then
    local pre_payload = resolved:sub(1, payload_start - 1)
    local payload_and_rest = resolved:sub(payload_start)
    
    local string_match = pre_payload:match('local%s+function%s+%w+%s*%([^)]*%)%s*return%s+R%s*%[%w+%+[^%]]+%]%s*end')
    if string_match then
        pre_payload = pre_payload:gsub('local%s+function%s+%w+%s*%([^)]*%)%s*return%s+R%s*%[%w+%+[^%]]+%]%s*end', '')
    end
    
    local shuffle_match = pre_payload:match('for%s+%w+[,]%w+%s+in%s+ipairs.-end%s*end%s*end')
    if shuffle_match then
        pre_payload = pre_payload:gsub('for%s+%w+[,]%w+%s+in%s+ipairs.-end%s*end%s*end', '-- [shuffle removed]')
    end
    
    local decoder_match = pre_payload:match('do%s+local%s+%w+=table%.concat.-end%s*end%s*end')
    if decoder_match then
        pre_payload = pre_payload:gsub('do%s+local%s+%w+=table%.concat.-end%s*end%s*end', '-- [decoder removed]')
    end
    
    table.insert(output_lines, "-- Bootstrap code:")
    table.insert(output_lines, pre_payload:gsub('%s+', ' '):sub(1, 500) .. "...")
    table.insert(output_lines, "")
    
    table.insert(output_lines, "-- VM Dispatcher (with resolved strings):")
    
    local dispatcher = payload_and_rest:match('while%s+%w+%s+do(.-)end%s*end%s*%w+%s*=%s*#')
    if dispatcher then
        local clean_dispatcher = dispatcher:gsub('(%w+)%[([^%]]+)%]%s*=%s*(%w+)%[([^%]]+)%]', function(t1, k1, t2, k2)
            return t1 .. "[" .. k1 .. "] = " .. t2 .. "[" .. k2 .. "]  -- MOVE"
        end)
        clean_dispatcher = clean_dispatcher:gsub('(%w+)%[([^%]]+)%]%s*=%s*"([^"]+)"', function(t, k, v)
            return t .. "[" .. k .. "] = \"" .. v .. "\"  -- LOADK"
        end)
        clean_dispatcher = clean_dispatcher:gsub('(%w+)%[([^%]]+)%]%s*=%s*(%w+)%s*%(', function(t, k, f)
            return t .. "[" .. k .. "] = " .. f .. "(...)  -- CLOSURE"
        end)
        
        for line in clean_dispatcher:gmatch("[^\n]+") do
            if line:find('"print"') or line:find('"pcall"') or line:find('"tostring"') 
                or line:find('"tonumber"') or line:find('"error"') or line:find('"table"')
                or line:find('"math"') or line:find('"floor"') or line:find('"char"')
                or line:find('"concat"') or line:find('"gsub"') or line:find('"byte"')
                or line:find('"len"') or line:find('"unpack"') or line:find('"gmatch"') then
                table.insert(output_lines, line)
            end
        end
    end
    
    table.insert(output_lines, "")
    table.insert(output_lines, "-- String Table:")
    table.insert(output_lines, "local R = {")
    for i, s in ipairs(decoded_strings) do
        table.insert(output_lines, '  [' .. i .. '] = "' .. s:gsub('\\', '\\\\'):gsub('"', '\\"') .. '",')
    end
    table.insert(output_lines, "}")
else
    table.insert(output_lines, resolved)
end

local output = table.concat(output_lines, "\n")
fs.writeFile(outFile, output)
