local args = {...}
local inputFile = args[1]
local outputFile = args[2]

local fs = require("@lune/fs")
local luau = require("@lune/luau")
local process = require("@lune/process")

local function readFile(path)
    return fs.readFile(path)
end

local function writeFile(path, content)
    return fs.writeFile(path, content)
end

local code = readFile(inputFile)

local envLogger = [[
local __env = getfenv()
local __logs = {}

local function __log(...)
    local args = {...}
    for i, v in ipairs(args) do
        if type(v) == "table" then
            args[i] = require("@lune/serde").stringify(v)
        end
    end
    table.insert(__logs, table.concat(args, " "))
end

local __handlers = {
    __index = function(t, k)
        if k == "print" then
            return __log
        end
        if k == "getfenv" then
            return function() return t end
        end
        if k == "loadstring" or k == "load" then
            return function(src, name)
                local fn, err = loadstring(src, name)
                if fn then
                    setfenv(fn, t)
                    return fn
                end
                return nil, err
            end
        end
        local val = __env[k]
        if type(val) == "function" then
            return function(...)
                __log(string.format("called %s", k))
                return val(...)
            end
        end
        return val
    end,
    __newindex = function(t, k, v)
        __log(string.format("%s = %s", k, tostring(v)))
        rawset(t, k, v)
    end
}

local __newEnv = setmetatable({}, __handlers)
setfenv(1, __newEnv)
]]

local fullCode = envLogger .. "\n" .. code .. "\n\nreturn table.concat(__logs, \"\\n\")"

local fn, err = luau.load(fullCode)
if not fn then
    writeFile(outputFile, "-- Failed to load: " .. tostring(err) .. "\n\n-- Original code:\n" .. code)
    print("Failed to load script")
    return
end

local success, result = pcall(fn)
if not success then
    writeFile(outputFile, "-- Runtime error: " .. tostring(result) .. "\n\n-- Original code:\n" .. code)
    print("Runtime error")
    return
end

local cleaned = result
cleaned = cleaned:gsub("called [a-zA-Z_]+", "")
cleaned = cleaned:gsub("%s+=", " =")
cleaned = cleaned:gsub("%s+%(", "(")
cleaned = cleaned:gsub("%)%s+", ") ")
cleaned = cleaned:gsub("%s+$", "")
cleaned = cleaned:gsub("^%s+", "")

if #cleaned < 50 then
    writeFile(outputFile, "-- No significant output captured\n\n-- Original code:\n" .. code)
    print("No output captured")
else
    writeFile(outputFile, "-- Deobfuscated using 25ms env logger\n\n" .. cleaned)
    print("Deobfuscation complete")
end
