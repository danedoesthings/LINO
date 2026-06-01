local fs = require("@lune/fs")
local luau = require("@lune/luau")
local process = require("@lune/process")

local targetFile = process.args[1] or "Test deobf.txt"
if not fs.isFile(targetFile) then
    error("Target obfuscated file not found.")
end

local inputSource = fs.readFile(targetFile)

local arrayName = inputSource:match("local%s+([%w_]+)%s*=%s*{")
local arrayStart = arrayName and inputSource:find("local%s+" .. arrayName .. "%s*=%s*{")

local initBlock
if arrayStart then
    local tail = inputSource:sub(arrayStart)
    local depth = 0
    local i = 1
    local cutPos = nil
    while i <= #tail do
        local c = tail:sub(i, i)
        if c == '"' or c == "'" then
            local q = c
            i = i + 1
            while i <= #tail and tail:sub(i, i) ~= q do
                if tail:sub(i, i) == '\\' then i = i + 1 end
                i = i + 1
            end
            i = i + 1
        elseif tail:sub(i, i+1) == '--' and tail:sub(i, i+3) ~= '--[[' then
            local nl = tail:find('\n', i + 2)
            i = nl and nl + 1 or #tail + 1
        elseif tail:sub(i, i+3) == '--[[' or tail:sub(i, i+1) == '[[' then
            local close = tail:find(']]', i + 2)
            i = close and close + 2 or #tail + 1
        else
            local kw = tail:match('^%f[%w_](function)%f[%W_]', i)
                    or tail:match('^%f[%w_](do)%f[%W_]', i)
                    or tail:match('^%f[%w_](end)%f[%W_]', i)
                    or tail:match('^%f[%w_](return)%f[%W_]', i)
            if kw == 'function' or kw == 'do' then
                depth = depth + 1
                i = i + #kw
            elseif kw == 'end' then
                depth = depth - 1
                i = i + #kw
            elseif kw == 'return' and depth == 0 then
                cutPos = i
                break
            else
                i = i + 1
            end
        end
    end
    if cutPos and cutPos > 1 then
        initBlock = tail:sub(1, cutPos - 1):gsub('%s+$', '')
    end
end

if not arrayName or not initBlock or initBlock == "" then
    local fallbackBlock = inputSource:match("^(.-)return%s*%(?%s*function")
    if fallbackBlock and fallbackBlock ~= "" then
        initBlock = fallbackBlock
        arrayName = arrayName or inputSource:match("local%s+([%w_]+)%s*=%s*{")
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
