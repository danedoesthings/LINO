import os, json, httpx, asyncio, re

ROBLOX_API_KEY = os.environ.get("ROBLOX_API_KEY", "")
ROBLOX_PLACE_ID = os.environ.get("ROBLOX_PLACE_ID", "")
ROBLOX_UNIVERSE_ID = os.environ.get("ROBLOX_UNIVERSE_ID", "")

BASE_URL = "https://apis.roblox.com/cloud/v2"
CREATE_TASK_URL = f"{BASE_URL}/universes/{ROBLOX_UNIVERSE_ID}/places/{ROBLOX_PLACE_ID}/luau-execution-session-tasks"

EXTRACT_TEMPLATE = r"""
local HttpService = game:GetService("HttpService")
local tableData = {__STRING_TABLE__}
local encoded = {}
for i, str in ipairs(tableData) do
    encoded[i] = str
end
return HttpService:JSONEncode({stringTable = encoded})
"""

def _find_table_literal_end(content, open_brace_index):
    depth = 0
    quote = None
    idx = open_brace_index
    while idx < len(content):
        char = content[idx]
        if quote:
            if char == "\\":
                idx += 2
                continue
            if char == quote:
                quote = None
            idx += 1
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
        idx += 1
    return -1

def _extract_string_table_from_source(content):
    m = re.search(r'local\s+\w+\s*=\s*\{', content)
    if not m:
        return None
    open_brace_index = content.find("{", m.start())
    table_end = _find_table_literal_end(content, open_brace_index)
    if table_end == -1:
        return None
    return content[open_brace_index:table_end]

async def execute_via_roblox(script_source):
    if not ROBLOX_API_KEY or not ROBLOX_PLACE_ID or not ROBLOX_UNIVERSE_ID:
        return None, "Roblox API not configured"

    table_body = _extract_string_table_from_source(script_source)
    if not table_body:
        return None, "Could not extract string table from script"

    extract_script = EXTRACT_TEMPLATE.replace("__STRING_TABLE__", table_body)

    headers = {
        "x-api-key": ROBLOX_API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "script": extract_script,
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
