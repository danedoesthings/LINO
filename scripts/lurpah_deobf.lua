local args = {...}
local inputFile = args[1]

local function readFile(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end

local code = readFile(inputFile)
if not code then
    print("Failed to read input file")
    return
end

local function extractLuraphContent(code)
    local patterns = {
        'return%s+function%s*%(([^)]*)%)%s*(.*)$',
        'local%s+_ENV%s*=%s*setmetatable%s*%(([^,]+),%s*{[^}]+}%)%s*(.*)$',
        'loadstring%s*%(([^)]+)%)%s*%(%)%s*$',
        'return%s+loadstring%s*%(([^)]+)%)%s*%(%)%s*$'
    }
    
    for _, pattern in ipairs(patterns) do
        local matches = {string.match(code, pattern)}
        if #matches > 0 then
            local result = table.concat(matches, "\n")
            result = result:gsub("^%s+", "")
            result = result:gsub("%s+$", "")
            if #result > 10 then
                return result
            end
        end
    end
    
    local functionDef = code:match("function%s+([a-zA-Z_][a-zA-Z0-9_]*)%s*%(([^)]*)%)%s*(.-)end%s*$")
    if functionDef then
        local name, params, body = functionDef
        return string.format("local %s = function(%s)\n%s\nend", name, params, body)
    end
    
    return nil
end

local extracted = extractLuraphContent(code)

if extracted then
    print("Deobfuscated successfully")
    print("-- Original code extracted --")
    print(extracted)
else
    local beautified = code
    beautified = beautified:gsub("local%s+_0x%x+%s*=%s*function%s*%(([^)]*)%)%s*local%s+_0x%x+%s*=%s*{}%s*(.-)end", "function(%1)\n%3\nend")
    beautified = beautified:gsub("_0x%x+%(", "(")
    beautified = beautified:gsub("_0x%x+", "var")
    beautified = beautified:gsub("bit32%.bxor%((%d+),%s*(%d+)%)", function(a, b)
        return tostring(tonumber(a) ~ tonumber(b) and 1 or 0)
    end)
    
    print("Partial deobfuscation:")
    print(beautified)
end
