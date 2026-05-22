import struct, re, hashlib
from collections import defaultdict

class BytecodeAnalyzer:
    LUA_SIGNATURE = b'\x1bLua'

    def __init__(self):
        self.known_patterns = {
            'lua51': {'version': 0x51, 'format': 0, 'endian': '<'},
            'lua52': {'version': 0x52, 'format': 0, 'endian': '<'},
            'lua53': {'version': 0x53, 'format': 0, 'endian': '<'},
            'lua54': {'version': 0x54, 'format': 0, 'endian': '<'},
        }

    def analyze(self, bytecode):
        if not bytecode or len(bytecode) < 12:
            return {'valid': False, 'reason': 'too_short'}
        if bytecode[:4] != self.LUA_SIGNATURE:
            return {'valid': False, 'reason': 'no_signature'}
        version = bytecode[4]
        format_ver = bytecode[5]
        endian = bytecode[6]
        int_size = bytecode[7]
        size_t_size = bytecode[8]
        instruction_size = bytecode[9]
        lua_number_size = bytecode[10]
        integral_flag = bytecode[11]
        return {
            'valid': True,
            'version': version,
            'format': format_ver,
            'endian': 'little' if endian == 1 else 'big',
            'int_size': int_size,
            'size_t_size': size_t_size,
            'instruction_size': instruction_size,
            'number_size': lua_number_size,
            'integral_flag': integral_flag,
            'total_size': len(bytecode),
            'sha256': hashlib.sha256(bytecode).hexdigest()[:16]
        }

    def extract_all_functions(self, bytecode):
        functions = []
        self._walk_functions(bytecode, 12, functions)
        return functions

    def _walk_functions(self, data, offset, functions, depth=0):
        if depth > 50 or offset >= len(data):
            return offset
        try:
            if offset + 16 > len(data):
                return offset
            header_size = data[offset - 7] if offset >= 7 else 12
            func_start = offset - header_size - 1 if offset >= header_size + 1 else offset
            func_info = {
                'offset': func_start,
                'header_size': header_size,
                'depth': depth
            }
            ptr = offset
            if ptr + 4 > len(data):
                return offset
            size_code = struct.unpack_from('<I', data, ptr)[0]
            ptr += 4 + size_code * 4
            if ptr + 4 > len(data):
                return offset
            size_constants = struct.unpack_from('<I', data, ptr)[0]
            ptr += 4
            constants = []
            for _ in range(size_constants):
                if ptr >= len(data):
                    break
                const_type = data[ptr]
                ptr += 1
                if const_type == 4:
                    if ptr + 4 > len(data):
                        break
                    str_len = struct.unpack_from('<I', data, ptr)[0]
                    ptr += 4
                    if ptr + str_len <= len(data):
                        constants.append(data[ptr:ptr+str_len])
                    ptr += str_len
                elif const_type == 3:
                    ptr += 8
                elif const_type == 1:
                    ptr += 1
            func_info['constants'] = constants
            functions.append(func_info)
            if ptr + 4 > len(data):
                return offset
            size_protos = struct.unpack_from('<I', data, ptr)[0]
            ptr += 4
            for _ in range(size_protos):
                ptr = self._walk_functions(data, ptr, functions, depth + 1)
            return ptr
        except Exception:
            return offset
