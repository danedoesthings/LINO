import urllib.request, os, shutil, sys

URLS = [
    "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/main/VirtualMachine.luau",
    "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/master/VirtualMachine.luau",
    "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/refs/heads/main/VirtualMachine.luau",
]

DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "renbex_vm.luau")

FALLBACK_VM = """\
local game = game or {}
local workspace = workspace or {}
game:GetService = game.GetService or function(name)
    local svc = {}
    setmetatable(svc, { __index = function() return function() end end })
    return svc
end
print("Renbex0 VM not available - using minimal stub")
"""

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

    print("All downloads failed – writing minimal Roblox stub")
    with open(DEST, 'w', encoding='utf-8') as f:
        f.write(FALLBACK_VM)

if __name__ == "__main__":
    download()
