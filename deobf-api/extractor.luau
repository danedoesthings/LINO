local fs = require("@lune/fs")
local luau = require("@lune/luau")
local process = require("@lune/process")

local targetFile = process.args[1] or "Test deobf.txt"
if not fs.isFile(targetFile) then
    error("Target obfuscated file not found.")
end

local inputSource = fs.readFile(targetFile)

local arrayName = inputSource:match("local%s+([%w_]+)%s*=%s*{")
local initBlock = inputSource:match("^(.-)return%s*%(?%s*function")

if not arrayName or not initBlock then
    local matrixBlock = inputSource:match("local R%s*=%s*(%b{})")
    if matrixBlock then
        arrayName = "R"
        initBlock = "local R = " .. matrixBlock
    else
        error("Could not locate string initialization block.")
    end
end

local cleanRunner = [[
    local fakeEnv = ...
    setfenv(1, fakeEnv)
]] .. "\n" .. initBlock .. "\nreturn " .. arrayName

local fakeEnv = {
    string = string, math = math, table = table,
    ipairs = ipairs, pairs = pairs, type = type,
    tonumber = tonumber, tostring = tostring, print = print
}
fakeEnv.getfenv = function() return fakeEnv end
fakeEnv.setfenv = function() end

local chunk, err = luau.load(cleanRunner)
if err then
    error("Failed to compile extraction block: " .. tostring(err))
end

local success, dictionaryTable = pcall(chunk, fakeEnv)
if not success then
    error("Runtime exception during evaluation: " .. tostring(dictionaryTable))
end

local cache = {}
for idx, val in pairs(dictionaryTable) do
    cache[tostring(idx)] = val
end

fs.writeFile("string_cache.json", require("@lune/net").jsonEncode(cache))
