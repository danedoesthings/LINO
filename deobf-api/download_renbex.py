import urllib.request, os, shutil

URLS = [
    "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/main/Sandbox.luau",
    "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/main/VM.luau",
    "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/refs/heads/main/Sandbox.luau",
]

DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "renbex_vm.luau")

def download():
    for url in URLS:
        try:
            print(f"Trying {url}")
            with urllib.request.urlopen(url, timeout=30) as resp:
                if resp.status == 200:
                    with open(DEST, 'wb') as f:
                        shutil.copyfileobj(resp, f)
                    print(f"Downloaded successfully from {url}")
                    return
        except Exception as e:
            print(f"Failed: {e}")
            continue

    print("All downloads failed — writing minimal stub")
    with open(DEST, 'w', encoding='utf-8') as f:
        f.write("""\
local game = game or {}
local workspace = workspace or {}
game:GetService = game.GetService or function(name)
    local svc = {}
    setmetatable(svc, { __index = function() return function() end end })
    return svc
end
print("Renbex0 VM stub loaded")
""")

if __name__ == "__main__":
    download()
