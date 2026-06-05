import os
import json
import httpx
import asyncio
from typing import Optional, List, Dict

ROBLOX_API_KEY = os.environ.get("ROBLOX_API_KEY", "")
ROBLOX_UNIVERSE_ID = os.environ.get("ROBLOX_UNIVERSE_ID", "")
ROBLOX_PLACE_ID = os.environ.get("ROBLOX_PLACE_ID", "")

BASE_URL = "https://apis.roblox.com/cloud/v2"

EXTRACT_TEMPLATE = r"""
local R = __STRING_TABLE__
local captured = {}
local captured_count = 0

local function capture(val)
    captured_count = captured_count + 1
    captured[captured_count] = val
end

local old_loadstring = loadstring
loadstring = function(src, name)
    capture(src)
    capture("[Payload: " .. #src .. " bytes]")
    return old_loadstring(src, name)
end

local old_getfenv = getfenv
getfenv = function(lvl)
    local env = old_getfenv(lvl)
    capture("[getfenv called]")
    return env
end

local old_print = print
print = function(...)
    local parts = {}
    for i = 1, select('#', ...) do
        parts[i] = tostring(select(i, ...))
    end
    capture(table.concat(parts, "\t"))
    old_print(...)
end

local f = loadstring(__OBFUSCATED_SOURCE__, "obfuscated")
if f then
    setfenv(f, getfenv())
    local success, result = pcall(f)
    if success then
        capture("[Execution complete]")
        if type(result) == "string" then
            capture(result)
        end
    else
        capture("[Error: " .. tostring(result) .. "]")
    end
end

local HttpService = game:GetService("HttpService")
return HttpService:JSONEncode({captured = captured, count = captured_count})
"""

class RobloxCloudExecutor:
    def __init__(self):
        self.api_key = ROBLOX_API_KEY
        self.universe_id = ROBLOX_UNIVERSE_ID
        self.place_id = ROBLOX_PLACE_ID
        self.available = bool(self.api_key and self.universe_id and self.place_id)

    async def execute(self, obfuscated_source: str, decoded_strings: List[str] = None, timeout: int = 120) -> Optional[Dict]:
        if not self.available:
            return None

        string_table = "{}"
        if decoded_strings:
            entries = []
            for i, s in enumerate(decoded_strings):
                if s:
                    escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                    entries.append(f'[{i + 1}] = "{escaped}"')
            string_table = "{" + ", ".join(entries) + "}"

        escaped_source = obfuscated_source.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        extract_script = EXTRACT_TEMPLATE.replace('__STRING_TABLE__', string_table)
        extract_script = extract_script.replace('__OBFUSCATED_SOURCE__', f'"{escaped_source}"')

        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }

        payload = {
            "script": extract_script,
            "arguments": []
        }

        create_url = f"{BASE_URL}/universes/{self.universe_id}/places/{self.place_id}/luau-execution-session-tasks"

        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                task_resp = await client.post(create_url, headers=headers, json=payload)
                if task_resp.status_code != 200:
                    return {"error": f"Task creation failed: {task_resp.status_code}", "details": task_resp.text}

                task_data = task_resp.json()
                task_path = task_data.get("path", "")
                if not task_path:
                    return {"error": "No task path returned"}

                task_url = f"https://apis.roblox.com{task_path}"

                for _ in range(60):
                    await asyncio.sleep(2)
                    poll_resp = await client.get(task_url, headers=headers)
                    if poll_resp.status_code != 200:
                        return {"error": f"Task poll failed: {poll_resp.status_code}"}

                    poll_data = poll_resp.json()
                    state = poll_data.get("state", "")

                    if state == "COMPLETED":
                        raw_output = poll_data.get("output", "")
                        try:
                            parsed = json.loads(raw_output)
                            return parsed
                        except json.JSONDecodeError:
                            return {"captured": [raw_output], "count": 1}
                    elif state == "FAILED":
                        return {"error": "Task failed", "details": poll_data.get("error", "Unknown error")}

                return {"error": "Task timed out after 120 seconds"}
            except Exception as e:
                return {"error": str(e)}
