local args = {...}
local inputFile = args[1]
local outputFile = args[2]

local function readFile(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end

local function writeFile(path, content)
    local f = io.open(path, "wb")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local code = readFile(inputFile)
if not code then
    print("Failed to read input file")
    return
end

local envLogger = [[
local _ENV = setmetatable({}, {__index = _G})
local fenv = getfenv()
local env = _G
local __log = {}
local __counter = 0

local function __add_log(msg)
    __counter = __counter + 1
    __log[__counter] = msg
end

local function __dump_string(str)
    local chunk, err = loadstring(str, "deobf")
    if not chunk then return "Error: " .. tostring(err) end
    setfenv(chunk, _ENV)
    local success, result = pcall(chunk)
    if not success then return "Runtime error: " .. tostring(result) end
    return table.concat(__log, "\n")
end

local mt = {
    __index = function(t, k)
        if k == "print" then
            return function(...)
                local args = {...}
                __add_log(table.concat(args, " "))
            end
        end
        return fenv[k] or env[k]
    end,
    __newindex = function(t, k, v)
        __add_log(string.format("%s = %s", k, tostring(v)))
        rawset(t, k, v)
    end
}

setmetatable(_ENV, mt)

_G.print = function(...)
    local args = {...}
    __add_log(table.concat(args, " "))
end
]]

local extractedCode = string.match(code, "return%s+function%(([^)]*)%)%s*(.*)$")
if extractedCode then
    local params, body = string.match(extractedCode, "^(.-)()(.*)$")
    if params and body then
        code = "local " .. params .. " = ...\n" .. body
    end
end

local fullCode = envLogger .. "\n" .. code .. "\n\nreturn __dump_string"

local tempFile = inputFile .. ".tmp"
writeFile(tempFile, fullCode)

local resultFile = outputFile or inputFile:gsub("%.lua$", "") .. "_deobf.lua"

local handle = io.popen('lua "' .. tempFile .. '" 2>&1', "r")
local output = handle:read("*all")
handle:close()

os.remove(tempFile)

if output and #output > 0 then
    local clean = output:gsub("Error: .-string.-:%d+:", "")
    clean = clean:gsub("Runtime error: .-string.-:%d+:", "")
    clean = clean:gsub("%[string \"deobf\"%]:%d+:", "")
    writeFile(resultFile, clean)
    print("Deobfuscation complete. Output saved to: " .. resultFile)
else
    writeFile(resultFile, "-- Deobfuscation failed\n-- Original code preserved\n\n" .. code)
    print("Deobfuscation produced no output")
end
