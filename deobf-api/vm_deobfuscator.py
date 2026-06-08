local function extract_vm_blocks(source)
    local blocks = {}
    local pos_var = nil
    local pos_match = source:match('while%s+(%w+)%s+do')
    if pos_match then
        pos_var = pos_match
    else
        pos_match = source:match('return%s*%(%s*function%s*%((%w+)')
        if pos_match then
            pos_var = pos_match
        end
    end
    if not pos_var then
        return nil
    end
    local pattern = 'if%s+' .. pos_var .. '%s*==%s*(%d+)%s+then%s*(.-)%s*elseif'
    local start_pos = 1
    while true do
        local block_id, block_code, next_pos = source:find(pattern, start_pos)
        if not block_id then
            break
        end
        blocks[tonumber(block_id)] = block_code
        start_pos = next_pos
    end
    local final_pattern = 'if%s+' .. pos_var .. '%s*==%s*(%d+)%s+then%s*(.-)%s*end'
    local block_id, block_code = source:match(final_pattern)
    if block_id then
        blocks[tonumber(block_id)] = block_code
    end
    return blocks, pos_var
end

local function extract_start_pos(source)
    local start_match = source:match('end%)%s*%(%s*(%d+)%s*%)')
    if start_match then
        return tonumber(start_match)
    end
    start_match = source:match('return%s*%(%s*function%s*%([^)]+%)%s*(%d+)%s*%)')
    if start_match then
        return tonumber(start_match)
    end
    return nil
end

local function linearize_blocks(blocks, start_pos)
    if not blocks or not start_pos then
        return nil
    end
    local order = {}
    local visited = {}
    local current = start_pos
    while current and not visited[current] do
        visited[current] = true
        order[#order + 1] = current
        local block = blocks[current]
        if block then
            local next_match = block:match(pos_var .. '%s*=%s*(%d+)')
            if next_match then
                current = tonumber(next_match)
            else
                break
            end
        else
            break
        end
    end
    local result = {}
    for _, id in ipairs(order) do
        if blocks[id] then
            local code = blocks[id]
            code = code:gsub(pos_var .. '%s*=%s*%d+', '')
            code = code:gsub('break', '')
            result[#result + 1] = code
        end
    end
    return table.concat(result, '\n')
end

local function extract_strings_direct(source)
    local strings = {}
    for match in source:gmatch('"(([^"\\]|\\.)*)"') do
        strings[#strings + 1] = match
    end
    return strings
end

local function is_printable(s)
    if #s < 5 then
        return false
    end
    local printable = 0
    for i = 1, #s do
        local b = s:byte(i)
        if (b >= 32 and b <= 126) or b == 10 or b == 13 or b == 9 then
            printable = printable + 1
        end
    end
    return printable / #s > 0.7
end

local function decode_string(s)
    local result = s
    if s:find('\\u') then
        result = result:gsub('\\u([0-9a-fA-F]{4})', function(hex)
            return string.char(tonumber(hex, 16))
        end)
    end
    if result:find('\\') then
        local octal_result = {}
        local i = 1
        while i <= #result do
            if result:sub(i, i) == '\\' and i + 1 <= #result then
                local octal = ''
                local j = i + 1
                while j <= #result and #octal < 3 and result:sub(j, j):match('[0-7]') do
                    octal = octal .. result:sub(j, j)
                    j = j + 1
                end
                if #octal > 0 then
                    octal_result[#octal_result + 1] = string.char(tonumber(octal, 8))
                    i = j
                else
                    octal_result[#octal_result + 1] = result:sub(i, i)
                    i = i + 1
                end
            else
                octal_result[#octal_result + 1] = result:sub(i, i)
                i = i + 1
            end
        end
        result = table.concat(octal_result)
    end
    return result
end

local function find_payload_in_strings(strings)
    for _, s in ipairs(strings) do
        local decoded = decode_string(s)
        if decoded:find('function') and decoded:find('local') and decoded:find('end') then
            return decoded
        end
        if decoded:find('print') and decoded:find('"') then
            return decoded
        end
    end
    return nil
end

local function extract_constant_table(source)
    local const_match = source:match('local%s+(%w+)%s*=%s*{([^}]+)}')
    if not const_match then
        return nil
    end
    local const_table = {}
    local const_name = const_match
    local body = const_match
    for value in body:gmatch('"([^"]+)"') do
        const_table[#const_table + 1] = value
    end
    return const_table, const_name
end

local function deobfuscate(source)
    local blocks, pos_var = extract_vm_blocks(source)
    if blocks and pos_var then
        local start_pos = extract_start_pos(source)
        if start_pos then
            local linear = linearize_blocks(blocks, start_pos)
            if linear and #linear > 50 then
                return linear, 'vm_linearized'
            end
        end
    end
    local strings = extract_strings_direct(source)
    if strings and #strings > 0 then
        local payload = find_payload_in_strings(strings)
        if payload then
            return payload, 'string_extract'
        end
    end
    local const_table, const_name = extract_constant_table(source)
    if const_table and const_name then
        local getter_pattern = const_name .. '%s*%[%s*%w+%s*%+%s*(%d+)%s*%]'
        local offset = source:match(getter_pattern)
        if offset then
            offset = tonumber(offset)
            if offset and const_table[offset] then
                local decoded = decode_string(const_table[offset])
                if decoded:find('function') or decoded:find('print') then
                    return decoded, 'constant_extract'
                end
            end
        end
        for i, s in ipairs(const_table) do
            local decoded = decode_string(s)
            if decoded:find('function') and decoded:find('end') then
                return decoded, 'constant_scan'
            end
        end
    end
    local simple_payload = source:match('print%(["\']([^"\']+)["\']%)')
    if simple_payload then
        return 'print("' .. simple_payload .. '")', 'simple_print'
    end
    return nil, 'no_method'
end

local args = {...}
local input_file = args[1]
local output_file = nil
for i = 1, #args do
    if args[i] == '-o' and i + 1 <= #args then
        output_file = args[i + 1]
        break
    end
end
if not input_file then
    io.stderr:write("Usage: lua vm_deobfuscator.lua input.lua [-o output.lua]\n")
    os.exit(1)
end
local file = io.open(input_file, "r")
if not file then
    io.stderr:write("Cannot open input file: " .. input_file .. "\n")
    os.exit(1)
end
local source = file:read("*a")
file:close()
local result, method = deobfuscate(source)
if not result then
    io.stderr:write("Deobfuscation failed: " .. method .. "\n")
    os.exit(1)
end
if output_file then
    local out = io.open(output_file, "w")
    if out then
        out:write("-- Deobfuscated using method: " .. method .. "\n\n" .. result)
        out:close()
    else
        io.stderr:write("Cannot write to output file: " .. output_file .. "\n")
        os.exit(1)
    end
else
    print(result)
end
os.exit(0)
