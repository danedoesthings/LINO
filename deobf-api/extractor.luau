local fs = require("@lune/fs")
local luau = require("@lune/luau")
local process = require("@lune/process")

local targetFile = process.args[1] or "Test deobf.txt"
if not fs.isFile(targetFile) then
    error("Target obfuscated file not found.")
end

local inputSource = fs.readFile(targetFile)

local capturedStrings = {}
local fakeEnv = {}

fakeEnv.string = setmetatable({}, {
    __index = function(_, key)
        return function(...)
            local result = string[key](...)
            if key == "char" or key == "sub" then
                table.insert(capturedStrings, tostring(result))
            end
            return result
        end
    end
})

fakeEnv.table = setmetatable({}, {
    __index = function(_, key)
        return table[key]
    end
})

fakeEnv.getfenv = function() return fakeEnv end
fakeEnv.setfenv = function() end
fakeEnv.require = function() return {} end

local matrixBlock = inputSource:match("local R%s*=%s*(%b{})")
if not matrixBlock then
    error("Failed to extract the string matrix structure statically.")
end

local cleanRunner = "local fakeEnv = ...\nsetfenv(1, fakeEnv)\nlocal R = " .. matrixBlock .. "\nreturn R"

local chunk, err = luau.load(cleanRunner)
if err then
    error("Failed to parse string matrix statically: " .. tostring(err))
end

local success, dictionaryTable = pcall(chunk, fakeEnv)
if not success then
    error("Runtime exception during sandboxed evaluation: " .. tostring(dictionaryTable))
end

local cache = {}
for idx, val in pairs(dictionaryTable) do
    cache[tostring(idx)] = val
end

fs.writeFile("string_cache.json", require("@lune/net").jsonEncode(cache))
