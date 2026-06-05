from .datatypes import Instance

class ServiceProvider:
    def __init__(self, emulator):
        self.emulator = emulator

    def setup(self):
        pass

    def get_service(self, name):
        return Instance(name, self.emulator)
