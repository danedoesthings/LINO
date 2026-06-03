local fs = require("@lune/fs")
local process = require("@lune/process")

local targetFile = process.args[1]
local outFile = process.args[2] or "deobfuscated.lua"
local stringsFile = process.args[3]

local input = fs.readFile(targetFile)

local decoded_strings = {}

if stringsFile and #stringsFile > 0 and fs.isFile(stringsFile) then
    local luau = require("@lune/luau")
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

local output_lines = {}
table.insert(output_lines, "-- Deobfuscated Output")
table.insert(output_lines, "-- " .. #decoded_strings .. " strings decoded by Python")
table.insert(output_lines, "")

table.insert(output_lines, "-- Resolved Source:")
table.insert(output_lines, input)
table.insert(output_lines, "")

if #decoded_strings > 0 then
    table.insert(output_lines, "-- Decoded String Table:")
    table.insert(output_lines, "local R = {")
    for i, s in ipairs(decoded_strings) do
        if s then
            local escaped = s:gsub('\\', '\\\\'):gsub('"', '\\"')
            table.insert(output_lines, '  [' .. i .. '] = "' .. escaped .. '",')
        end
    end
    table.insert(output_lines, "}")
end

local output = table.concat(output_lines, "\n")
fs.writeFile(outFile, output)
