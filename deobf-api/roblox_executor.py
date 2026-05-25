import os, json, httpx

ROBLOX_API_KEY = os.environ.get("ROBLOX_API_KEY", "")
ROBLOX_PLACE_ID = os.environ.get("ROBLOX_PLACE_ID", "")
ROBLOX_UNIVERSE_ID = os.environ.get("ROBLOX_UNIVERSE_ID", "")

BASE_URL = "https://apis.roblox.com/cloud/v2"
CREATE_TASK_URL = f"{BASE_URL}/universes/{ROBLOX_UNIVERSE_ID}/places/{ROBLOX_PLACE_ID}/luau-execution-session-tasks"

HOOK_TEMPLATE = """
local HttpService = game:GetService("HttpService")
local scriptContent = [[{}]]
local func, err = loadstring(scriptContent)
if not func then
    return HttpService:JSONEncode({error = "Compile error: " .. tostring(err)})
end
local success, result = pcall(func)
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

    hook_script = HOOK_TEMPLATE.replace("{}", script_source.replace("\\", "\\\\").replace('"', '\\"'))
    payload = {
        "script": hook_script,
        "arguments": []
    }

    async with httpx.AsyncClient(timeout=120) as client:
        try:
            task_response = await client.post(CREATE_TASK_URL, headers=headers, json=payload)
            if task_response.status_code != 200:
                return None, f"Task creation failed: {task_response.status_code} - {task_response.text}"

            task_data = task_response.json()
            task_path = task_data.get("path", "")

            if not task_path:
                return None, "No task path returned"

            task_url = f"https://apis.roblox.com{task_path}"

            for _ in range(30):
                await asyncio.sleep(2)
                poll_response = await client.get(task_url, headers=headers)
                if poll_response.status_code != 200:
                    return None, f"Task poll failed: {poll_response.status_code}"

                poll_data = poll_response.json()
                state = poll_data.get("state", "")

                if state == "COMPLETED":
                    results = poll_data.get("output", "")
                    try:
                        parsed = json.loads(results)
                        if "output" in parsed:
                            return parsed["output"], None
                        elif "error" in parsed:
                            return None, parsed["error"]
                    except:
                        return results, None
                elif state == "FAILED":
                    return None, f"Task failed: {poll_data.get('error', 'Unknown error')}"

            return None, "Task timed out"

        except Exception as e:
            return None, str(e)
