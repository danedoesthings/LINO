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

def _extract_string_table_from_source(source):
    patterns = [
        r'return\s+(?:\(\s*)?function\s*\([^)]*\)[^\{]*(\{.*?\})\s*end\s*(?:\))?\s*\(',
        r'local\s+\w+\s*=\s*(\{.*?\})\s*;?\s*return',
        r'=\s*(\{.*?\})\s*;?\s*return',
    ]
    for pat in patterns:
        m = re.search(pat, source, re.DOTALL)
        if m:
            return m.group(1)
    for m in re.finditer(r'\{', source):
        body = _extract_balanced(source, m.start())
        if body and body.count('"') > 20:
            return body
    return None

def _extract_balanced(code, start):
    if start >= len(code) or code[start] != '{':
        return None
    depth = 0
    in_str = False
    str_char = None
    i = start
    while i < len(code):
        c = code[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == str_char:
                in_str = False
        else:
            if c in ('"', "'"):
                in_str = True
                str_char = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return code[start:i+1]
        i += 1
    return None


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
