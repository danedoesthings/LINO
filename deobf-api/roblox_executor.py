import os, json, httpx, asyncio

ROBLOX_API_KEY = os.environ.get("ROBLOX_API_KEY", "")
ROBLOX_PLACE_ID = os.environ.get("ROBLOX_PLACE_ID", "")
ROBLOX_UNIVERSE_ID = os.environ.get("ROBLOX_UNIVERSE_ID", "")

BASE_URL = "https://apis.roblox.com/cloud/v2"
CREATE_TASK_URL = f"{BASE_URL}/universes/{ROBLOX_UNIVERSE_ID}/places/{ROBLOX_PLACE_ID}/luau-execution-session-tasks"

HOOK_TEMPLATE = r"""
local HttpService = game:GetService("HttpService")

local realLoadstring = loadstring
local captured = {}

_G.loadstring = function(code, chunkname)
    if type(code) == "string" then
        table.insert(captured, code)
    end
    return realLoadstring(code, chunkname)
end
_G.load = _G.loadstring

local scriptContent = [[{}]]
local func, compileErr = realLoadstring(scriptContent)

if not func then
    _G.loadstring = realLoadstring
    _G.load = realLoadstring
    return HttpService:JSONEncode({error = "Compile error: " .. tostring(compileErr)})
end

local success, result = pcall(func)

_G.loadstring = realLoadstring
_G.load = realLoadstring

if #captured > 0 then
    return HttpService:JSONEncode({output = table.concat(captured, "\n")})
end

local foundTable = nil
for k, v in pairs(getfenv(0)) do
    if type(v) == "table" and #v > 10 and k ~= "shared" and k ~= "syn" and k ~= "_G" and k ~= "package" then
        local stringCount = 0
        for i, entry in ipairs(v) do
            if type(entry) == "string" then
                stringCount = stringCount + 1
            end
        end
        if stringCount > 10 then
            foundTable = v
            break
        end
    end
end

if foundTable then
    local encodedStrings = {}
    for i, str in ipairs(foundTable) do
        encodedStrings[i] = str
    end
    return HttpService:JSONEncode({stringTable = encodedStrings})
end

if not success then
    return HttpService:JSONEncode({error = "Runtime error: " .. tostring(result)})
end

return HttpService:JSONEncode({output = tostring(result)})
"""

async def execute_via_roblox(script_source):
    if not ROBLOX_API_KEY or not ROBLOX_PLACE_ID or not ROBLOX_UNIVERSE_ID:
        return None, "Roblox API not configured"

    headers = {
        "x-api-key": ROBLOX_API_KEY,
        "Content-Type": "application/json"
    }

    escaped_source = script_source.replace("\\", "\\\\").replace('"', '\\"')
    hook_script = HOOK_TEMPLATE.replace("{}", escaped_source)

    payload = {
        "script": hook_script,
        "arguments": []
    }

    async with httpx.AsyncClient(timeout=120) as client:
        try:
            task_resp = await client.post(CREATE_TASK_URL, headers=headers, json=payload)
            if task_resp.status_code != 200:
                return None, f"Task creation failed: {task_resp.status_code} - {task_resp.text}"

            task_data = task_resp.json()
            task_path = task_data.get("path", "")
            if not task_path:
                return None, "No task path returned"

            task_url = f"https://apis.roblox.com{task_path}"

            for _ in range(30):
                await asyncio.sleep(2)
                poll_resp = await client.get(task_url, headers=headers)
                if poll_resp.status_code != 200:
                    return None, f"Task poll failed: {poll_resp.status_code}"

                poll_data = poll_resp.json()
                state = poll_data.get("state", "")

                if state == "COMPLETED":
                    raw_output = poll_data.get("output", "")
                    try:
                        parsed = json.loads(raw_output)
                        if "stringTable" in parsed:
                            return parsed["stringTable"], None
                        elif "output" in parsed:
                            return parsed["output"], None
                        elif "error" in parsed:
                            return None, parsed["error"]
                    except:
                        return raw_output, None
                elif state == "FAILED":
                    return None, f"Task failed: {poll_data.get('error', 'Unknown error')}"

            return None, "Task timed out"

        except Exception as e:
            return None, str(e)
