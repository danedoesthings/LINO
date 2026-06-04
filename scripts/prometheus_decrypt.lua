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

local function extractEncryptionKeys(code)
    local keys = {}
    
    local paramMul45 = code:match("param_mul_45%s*=%s*(%d+)")
    local paramMul8 = code:match("param_mul_8%s*=%s*(%d+)")
    local paramAdd45 = code:match("param_add_45%s*=%s*(%d+)")
    local secretKey8 = code:match("secret_key_8%s*=%s*(%d+)")
    
    if paramMul45 then keys.param_mul_45 = tonumber(paramMul45) end
    if paramMul8 then keys.param_mul_8 = tonumber(paramMul8) end
    if paramAdd45 then keys.param_add_45 = tonumber(paramAdd45) end
    if secretKey8 then keys.secret_key_8 = tonumber(secretKey8) end
    
    local strings = {}
    local stringPattern = '{[%s]*"\\x[^"]+",%s*(%d+)[%s]*}'
    for match in code:gmatch(stringPattern) do
        table.insert(strings, match)
    end
    
    return keys, strings
end

local keys, encryptedStrings = extractEncryptionKeys(code)

if keys.param_mul_45 and keys.param_mul_8 then
    local decryptor = string.format([[
        local floor = math.floor
        local random = math.random
        local remove = table.remove
        local char = string.char
        
        local state_45 = 0
        local state_8 = 2
        local charmap = {}
        local nums = {}
        
        for i = 1, 256 do nums[i] = i end
        
        repeat
            local idx = random(1, #nums)
            local n = remove(nums, idx)
            charmap[n] = char(n - 1)
        until #nums == 0
        
        local prev_values = {}
        
        local function get_next_pseudo_random_byte()
            if #prev_values == 0 then
                state_45 = (state_45 * %d + %d) %% 35184372088832
                repeat
                    state_8 = state_8 * %d %% 257
                until state_8 ~= 1
                local r = state_8 %% 32
                local n = floor(state_45 / 2 ^ (13 - (state_8 - r) / 32)) %% 2 ^ 32 / 2 ^ r
                local rnd = floor(n %% 1 * 2 ^ 32) + floor(n)
                local low_16 = rnd %% 65536
                local high_16 = (rnd - low_16) / 65536
                local b1 = low_16 %% 256
                local b2 = (low_16 - b1) / 256
                local b3 = high_16 %% 256
                local b4 = (high_16 - b3) / 256
                prev_values = { b1, b2, b3, b4 }
            end
            return table.remove(prev_values)
        end
        
        local function decrypt(str, seed)
            prev_values = {}
            state_45 = seed %% 35184372088832
            state_8 = seed %% 255 + 2
            local out = ""
            local prevVal = %d
            for i = 1, #str do
                local byte = string.byte(str, i)
                local dec = (byte - (get_next_pseudo_random_byte() + prevVal)) %% 256
                out = out .. charmap[dec + 1]
                prevVal = dec
            end
            return out
        end
    ]], keys.param_mul_45 or 221, keys.param_add_45 or 11819332359551, keys.param_mul_8 or 203, keys.secret_key_8 or 15)
    
    local decrypted = {}
    for i, seed in ipairs(encryptedStrings) do
        local encryptedPattern = string.format('{"\\x[^"]+",%s}', seed)
        local encryptedStr = code:match(encryptedPattern)
        if encryptedStr then
            local str = encryptedStr:match('"([^"]+)"')
            if str then
                local decryptedStr = decrypt(str, tonumber(seed))
                table.insert(decrypted, decryptedStr)
            end
        end
    end
    
    if #decrypted > 0 then
        local result = table.concat(decrypted, "\n")
        if outputFile then
            writeFile(outputFile, result)
        else
            print(result)
        end
        print("Decryption successful")
        return
    end
end

print("Could not extract encryption keys. Attempting runtime extraction...")

local runtimeExtractor = code .. [[

local __decrypted_strings = {}
local __hook = setmetatable({}, {
    __index = function(t, k)
        if k == "STRINGS" or k == "realStrings" then
            return __decrypted_strings
        end
        return nil
    end
})

local env = getfenv()
setfenv(1, __hook)

pcall(function()
    -- Trigger string decryption
    for k, v in pairs(__decrypted_strings) do
        print(v)
    end
end)

for k, v in pairs(__decrypted_strings) do
    if type(v) == "string" and #v > 0 then
        print(v)
    end
end
]]

local handle = io.popen('lua -e "' .. runtimeExtractor:gsub('"', '\\"') .. '" 2>&1', "r")
local output = handle:read("*all")
handle:close()

if output and #output > 0 then
    if outputFile then
        writeFile(outputFile, output)
    else
        print(output)
    end
    print("Runtime extraction successful")
else
    print("No strings extracted")
end
