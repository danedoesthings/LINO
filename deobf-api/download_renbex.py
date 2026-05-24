import urllib.request, os, shutil

RENBEX_URL = "https://raw.githubusercontent.com/Renbex0/Virtual-Machine/main/VirtualMachine.luau"
DEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "renbex_vm.luau")

def download():
    print(f"Downloading Renbex0 Virtual Machine to {DEST}")
    with urllib.request.urlopen(RENBEX_URL) as resp, open(DEST, 'wb') as f:
        shutil.copyfileobj(resp, f)

if __name__ == "__main__":
    download()
