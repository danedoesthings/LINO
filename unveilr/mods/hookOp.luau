-- HookOp module for UnveilR - Pass-through version
local fs = require("@lune/fs")
local process = require("@lune/process")

local args = process.args
local inputPath = args[2]
local outputPath = args[3]

if not inputPath or not outputPath then
    io.stderr:write("hookOp: missing input or output path\n")
    process.exit(1)
end

local ok, content = pcall(fs.readFile, inputPath)
if not ok then
    io.stderr:write("hookOp: failed to read input: " .. tostring(content) .. "\n")
    process.exit(1)
end

-- Simple pass-through - just copy the file
local ok2, err = pcall(fs.writeFile, outputPath, content)
if not ok2 then
    io.stderr:write("hookOp: failed to write output: " .. tostring(err) .. "\n")
    process.exit(1)
end

process.exit(0)
