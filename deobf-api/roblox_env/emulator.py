import re
import math
import random
from typing import Any, Dict, List, Optional, Tuple
from .globals import RobloxGlobals
from .datatypes import Instance, Vector3, CFrame, Color3, UDim2
from .services import ServiceProvider
from .executor import Executor

class RobloxEmulator:
    def __init__(self, decoded_strings: List[str] = None):
        self.decoded_strings = decoded_strings or []
        self.globals = RobloxGlobals(self)
        self.services = ServiceProvider(self)
        self.executor = Executor(self)
        self.output: List[str] = []
        self._setup_environment()

    def _setup_environment(self):
        self.globals.setup()
        self.services.setup()
        if self.decoded_strings:
            self._inject_string_table()

    def _inject_string_table(self):
        R = {}
        for i, s in enumerate(self.decoded_strings):
            if s:
                R[i + 1] = s
        self.globals.set('R', R)
        self.globals.set('EncStr', R)

    def capture(self, value: str):
        if isinstance(value, str) and len(value) > 0:
            self.output.append(value)

    def execute(self, source: str) -> str:
        self.output = []
        try:
            self.executor.run(source)
        except Exception as e:
            self.output.append(f"-- [Emulator Error] {e}")
        return '\n'.join(self.output) if self.output else '-- [Emulator] No output'

    def get_output(self) -> str:
        return '\n'.join(self.output) if self.output else '-- [Emulator] No output'
