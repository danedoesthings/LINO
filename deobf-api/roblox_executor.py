import os, json, httpx, time, base64

ROBLOX_API_KEY = os.environ.get("ROBLOX_API_KEY", "")
ROBLOX_PLACE_ID = os.environ.get("ROBLOX_PLACE_ID", "")
ROBLOX_UNIVERSE_ID = os.environ.get("ROBLOX_UNIVERSE_ID", "")

ROBLOX_UPLOAD_URL = f"https://apis.roblox.com/universes/v1/{ROBLOX_UNIVERSE_ID}/places/{ROBLOX_PLACE_ID}/scripts"
ROBLOX_EXECUTE_URL = f"https://apis.roblox.com/cloud/v2/universes/{ROBLOX_UNIVERSE_ID}/places/{ROBLOX_PLACE_ID}/scripts:execute"

HOOK_SCRIPT = """
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")

local originalRequire = require
local captured = {}

local function capture(name, source)
    table.insert(captured, {name = name, source = source})
end

local env = setmetatable({}, {__index = getfenv()})
env.require = function(module)
    local result = originalRequire(module)
    capture(tostring(module), "module")
    return result
end

local scriptContent = [[{}]]
local func, err = loadstring(scriptContent)
if not func then
    return HttpService:JSONEncode({error = "Compilation error: " .. tostring(err)})
end

setfenv(func, env)
local success, result = pcall(func)
if not success then
    return HttpService:JSONEncode({error = "Runtime error: " .. tostring(result)})
end

local sources = {}
for _, v in ipairs(captured) do
    table.insert(sources, v.source)
end

local output = table.concat(sources, "\\n")
return HttpService:JSONEncode({output = output})
"""

async def execute_via_roblox(script_source):
    if not ROBLOX_API_KEY or not ROBLOX_PLACE_ID or not ROBLOX_UNIVERSE_ID:
        return None, "Roblox API not configured"
    
    headers = {
        "x-api-key": ROBLOX_API_KEY,
        "Content-Type": "application/json"
    }
    
    hook_with_script = HOOK_SCRIPT.replace("{}", script_source.replace("\\", "\\\\").replace('"', '\\"'))
    payload = {
        "script": hook_with_script,
        "runtime": "Legacy",
        "arguments": []
    }
    
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            response = await client.post(ROBLOX_EXECUTE_URL, headers=headers, json=payload)
            if response.status_code == 200:
                data = response.json()
                result = data.get("results", "")
                try:
                    result_json = json.loads(result)
                    if "output" in result_json:
                        return result_json["output"], None
                    elif "error" in result_json:
                        return None, result_json["error"]
                except:
                    return result, None
            else:
                return None, f"Roblox API error: {response.status_code} - {response.text}"
        except Exception as e:
            return None, str(e)
