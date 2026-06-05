import re
from typing import Dict, Any

class Executor:
    def __init__(self, emulator):
        self.emulator = emulator

    def run(self, source: str):
        g = self.emulator.globals._globals
        try:
            exec(source, g)
        except Exception as e:
            self.emulator.capture(f"[Executor Error] {e}")
