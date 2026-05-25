import os, json, httpx, asyncio

ROBLOX_API_KEY = os.environ.get("ROBLOX_API_KEY", "")
ROBLOX_PLACE_ID = os.environ.get("ROBLOX_PLACE_ID", "")
ROBLOX_UNIVERSE_ID = os.environ.get("ROBLOX_UNIVERSE_ID", "")

BASE_URL = "https://apis.roblox.com/cloud/v2"
CREATE_TASK_URL = f"{BASE_URL}/universes/{ROBLOX_UNIVERSE_ID}/places/{ROBLOX_PLACE_ID}/luau-execution-session-tasks"

HOOK_TEMPLATE = r"""
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")

local captured = {}
local originalLoadstring = loadstring

local function hookLoadstring(code, chunkname)
    if type(code) == "string" then
        table.insert(captured, code)
    end
    return originalLoadstring(code, chunkname)
end

local env = getfenv()
env.loadstring = hookLoadstring
env.require = function(module)
    local result = originalRequire(module)
    return result
end
setmetatable(env, {__index = getfenv(0)})

local scriptContent = [[{}]]
local func, compileErr = originalLoadstring(scriptContent)
if not func then
    return HttpService:JSONEncode({error = "Compile error: " .. tostring(compileErr)})
end

setfenv(func, env)
local success, result = pcall(func)

local allSources = table.concat(captured, "\n")

if #allSources > 0 then
    return HttpService:JSONEncode({output = allSources})
elseif not success then
    return HttpService:JSONEncode({error = "Runtime error: " .. tostring(result)})
else
    return HttpService:JSONEncode({output = tostring(result)})
end
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
                        if "output" in parsed:
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
