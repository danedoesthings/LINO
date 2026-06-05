import math
import random
from typing import Any, Tuple as TupleType

class RobloxType:
    def __init__(self, typename: str):
        self._typename = typename

    def __repr__(self):
        return f"{self._typename}()"

class Vector3(RobloxType):
    def __init__(self, x: float = 0, y: float = 0, z: float = 0):
        super().__init__("Vector3")
        self.x = x
        self.y = y
        self.z = z

    @property
    def magnitude(self):
        return math.sqrt(self.x ** 2 + self.y ** 2 + self.z ** 2)

    @property
    def unit(self):
        mag = self.magnitude
        if mag == 0:
            return Vector3(0, 0, 0)
        return Vector3(self.x / mag, self.y / mag, self.z / mag)

    def __add__(self, other):
        if isinstance(other, Vector3):
            return Vector3(self.x + other.x, self.y + other.y, self.z + other.z)
        return Vector3(self.x + other, self.y + other, self.z + other)

    def __sub__(self, other):
        if isinstance(other, Vector3):
            return Vector3(self.x - other.x, self.y - other.y, self.z - other.z)
        return Vector3(self.x - other, self.y - other, self.z - other)

    def __mul__(self, other):
        if isinstance(other, Vector3):
            return Vector3(self.x * other.x, self.y * other.y, self.z * other.z)
        return Vector3(self.x * other, self.y * other, self.z * other)

    def __truediv__(self, other):
        if isinstance(other, Vector3):
            return Vector3(self.x / other.x, self.y / other.y, self.z / other.z)
        return Vector3(self.x / other, self.y / other, self.z / other)

    def __eq__(self, other):
        if isinstance(other, Vector3):
            return self.x == other.x and self.y == other.y and self.z == other.z
        return False

    def __repr__(self):
        return f"Vector3.new({self.x}, {self.y}, {self.z})"

    @staticmethod
    def new(x=0, y=0, z=0):
        return Vector3(x, y, z)

    def Dot(self, other):
        return self.x * other.x + self.y * other.y + self.z * other.z

    def Cross(self, other):
        return Vector3(
            self.y * other.z - self.z * other.y,
            self.z * other.x - self.x * other.z,
            self.x * other.y - self.y * other.x
        )

class Vector2(RobloxType):
    def __init__(self, x: float = 0, y: float = 0):
        super().__init__("Vector2")
        self.x = x
        self.y = y

    @property
    def magnitude(self):
        return math.sqrt(self.x ** 2 + self.y ** 2)

    def __add__(self, other):
        if isinstance(other, Vector2):
            return Vector2(self.x + other.x, self.y + other.y)
        return Vector2(self.x + other, self.y + other)

    def __sub__(self, other):
        if isinstance(other, Vector2):
            return Vector2(self.x - other.x, self.y - other.y)
        return Vector2(self.x - other, self.y - other)

    def __mul__(self, other):
        if isinstance(other, Vector2):
            return Vector2(self.x * other.x, self.y * other.y)
        return Vector2(self.x * other, self.y * other)

    def __repr__(self):
        return f"Vector2.new({self.x}, {self.y})"

    @staticmethod
    def new(x=0, y=0):
        return Vector2(x, y)

class CFrame(RobloxType):
    def __init__(self, *args):
        super().__init__("CFrame")
        if len(args) == 0:
            self._matrix = (1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1)
        elif len(args) == 3:
            x, y, z = args
            self._matrix = (1, 0, 0, x, 0, 1, 0, y, 0, 0, 1, z, 0, 0, 0, 1)
        elif len(args) == 12:
            self._matrix = tuple(args)

    @property
    def p(self):
        return Vector3(self._matrix[3], self._matrix[7], self._matrix[11])

    @property
    def XVector(self):
        return Vector3(self._matrix[0], self._matrix[4], self._matrix[8])

    @property
    def YVector(self):
        return Vector3(self._matrix[1], self._matrix[5], self._matrix[9])

    @property
    def ZVector(self):
        return Vector3(self._matrix[2], self._matrix[6], self._matrix[10])

    @property
    def LookVector(self):
        return -self.ZVector

    def __mul__(self, other):
        if isinstance(other, CFrame):
            a = self._matrix
            b = other._matrix
            return CFrame(
                a[0]*b[0] + a[1]*b[4] + a[2]*b[8],
                a[0]*b[1] + a[1]*b[5] + a[2]*b[9],
                a[0]*b[2] + a[1]*b[6] + a[2]*b[10],
                a[0]*b[3] + a[1]*b[7] + a[2]*b[11] + a[3],
                a[4]*b[0] + a[5]*b[4] + a[6]*b[8],
                a[4]*b[1] + a[5]*b[5] + a[6]*b[9],
                a[4]*b[2] + a[5]*b[6] + a[6]*b[10],
                a[4]*b[3] + a[5]*b[7] + a[6]*b[11] + a[7],
                a[8]*b[0] + a[9]*b[4] + a[10]*b[8],
                a[8]*b[1] + a[9]*b[5] + a[10]*b[9],
                a[8]*b[2] + a[9]*b[6] + a[10]*b[10],
                a[8]*b[3] + a[9]*b[7] + a[10]*b[11] + a[11],
            )
        elif isinstance(other, Vector3):
            a = self._matrix
            return Vector3(
                a[0]*other.x + a[1]*other.y + a[2]*other.z + a[3],
                a[4]*other.x + a[5]*other.y + a[6]*other.z + a[7],
                a[8]*other.x + a[9]*other.y + a[10]*other.z + a[11],
            )
        return NotImplemented

    def __repr__(self):
        return f"CFrame.new({self.p.x}, {self.p.y}, {self.p.z})"

    @staticmethod
    def new(*args):
        return CFrame(*args)

    def inverse(self):
        a = self._matrix
        det = a[0]*a[5]*a[10] + a[1]*a[6]*a[8] + a[2]*a[4]*a[9] - a[2]*a[5]*a[8] - a[1]*a[4]*a[10] - a[0]*a[6]*a[9]
        if det == 0:
            return CFrame()
        inv_det = 1 / det
        return CFrame(
            (a[5]*a[10] - a[6]*a[9]) * inv_det,
            (a[2]*a[9] - a[1]*a[10]) * inv_det,
            (a[1]*a[6] - a[2]*a[5]) * inv_det,
            -(a[3]*((a[5]*a[10] - a[6]*a[9]) * inv_det) + a[7]*((a[2]*a[9] - a[1]*a[10]) * inv_det) + a[11]*((a[1]*a[6] - a[2]*a[5]) * inv_det)),
            (a[6]*a[8] - a[4]*a[10]) * inv_det,
            (a[0]*a[10] - a[2]*a[8]) * inv_det,
            (a[2]*a[4] - a[0]*a[6]) * inv_det,
            -(a[3]*((a[6]*a[8] - a[4]*a[10]) * inv_det) + a[7]*((a[0]*a[10] - a[2]*a[8]) * inv_det) + a[11]*((a[2]*a[4] - a[0]*a[6]) * inv_det)),
            (a[4]*a[9] - a[5]*a[8]) * inv_det,
            (a[1]*a[8] - a[0]*a[9]) * inv_det,
            (a[0]*a[5] - a[1]*a[4]) * inv_det,
            -(a[3]*((a[4]*a[9] - a[5]*a[8]) * inv_det) + a[7]*((a[1]*a[8] - a[0]*a[9]) * inv_det) + a[11]*((a[0]*a[5] - a[1]*a[4]) * inv_det)),
        )

class Color3(RobloxType):
    def __init__(self, r: float = 0, g: float = 0, b: float = 0):
        super().__init__("Color3")
        self.r = r
        self.g = g
        self.b = b

    def __repr__(self):
        return f"Color3.new({self.r}, {self.g}, {self.b})"

    @staticmethod
    def new(r=0, g=0, b=0):
        return Color3(r, g, b)

    @staticmethod
    def fromRGB(r, g, b):
        return Color3(r / 255, g / 255, b / 255)

class UDim2(RobloxType):
    def __init__(self, x_scale=0, x_offset=0, y_scale=0, y_offset=0):
        super().__init__("UDim2")
        self.X = UDim(x_scale, x_offset)
        self.Y = UDim(y_scale, y_offset)

    def __repr__(self):
        return f"UDim2.new({self.X.Scale}, {self.X.Offset}, {self.Y.Scale}, {self.Y.Offset})"

    @staticmethod
    def new(x_scale=0, x_offset=0, y_scale=0, y_offset=0):
        return UDim2(x_scale, x_offset, y_scale, y_offset)

class UDim:
    def __init__(self, scale=0, offset=0):
        self.Scale = scale
        self.Offset = offset

    def __repr__(self):
        return f"UDim.new({self.Scale}, {self.Offset})"

class Instance(RobloxType):
    def __init__(self, class_name: str = "Instance", emulator=None):
        super().__init__(class_name)
        self.ClassName = class_name
        self.Name = class_name
        self.Parent = None
        self.Children = []
        self._properties: Dict[str, Any] = {}
        self._emulator = emulator

    def __getattr__(self, name):
        if name in self._properties:
            return self._properties[name]
        if name == 'GetService' and self.ClassName == 'game':
            return lambda s: Instance(s, self._emulator)
        return Instance(name, self._emulator)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            super().__setattr__(name, value)
        else:
            self._properties[name] = value
            if self._emulator and isinstance(value, str) and len(value) > 3:
                self._emulator.capture(value)

    def __call__(self, *args, **kwargs):
        return Instance(f"{self.ClassName}(...)", self._emulator)

    def __repr__(self):
        return self.ClassName

    @staticmethod
    def new(class_name, emulator=None):
        return Instance(class_name, emulator)

class BrickColor(RobloxType):
    def __init__(self, name="Medium stone grey"):
        super().__init__("BrickColor")
        self.Name = name
        self.Color = Color3(0.5, 0.5, 0.5)

    @staticmethod
    def new(val):
        return BrickColor(str(val))

    @staticmethod
    def random():
        return BrickColor()

class TweenInfo(RobloxType):
    def __init__(self, time=1, easing_style=None, easing_direction=None, repeat_count=0, reverses=False, delay_time=0):
        super().__init__("TweenInfo")
        self.Time = time

    @staticmethod
    def new(time=1, easing_style=None, easing_direction=None, repeat_count=0, reverses=False, delay_time=0):
        return TweenInfo(time, easing_style, easing_direction, repeat_count, reverses, delay_time)

class Ray(RobloxType):
    def __init__(self, origin=None, direction=None):
        super().__init__("Ray")
        self.Origin = origin or Vector3()
        self.Direction = direction or Vector3()

    @staticmethod
    def new(origin=None, direction=None):
        return Ray(origin, direction)

class Region3(RobloxType):
    def __init__(self, min_pos=None, max_pos=None):
        super().__init__("Region3")
        self.Min = min_pos or Vector3()
        self.Max = max_pos or Vector3()

    @staticmethod
    def new(min_pos=None, max_pos=None):
        return Region3(min_pos, max_pos)

class NumberRange(RobloxType):
    def __init__(self, min_val=0, max_val=0):
        super().__init__("NumberRange")
        self.Min = min_val
        self.Max = max_val

    @staticmethod
    def new(min_val, max_val):
        return NumberRange(min_val, max_val)

class NumberSequence:
    pass

class PhysicalProperties(RobloxType):
    def __init__(self):
        super().__init__("PhysicalProperties")

    @staticmethod
    def new(*args):
        return PhysicalProperties()

class EnumItem:
    def __init__(self, name: str, value: int):
        self.Name = name
        self.Value = value

    def __repr__(self):
        return self.Name

    def __eq__(self, other):
        if isinstance(other, EnumItem):
            return self.Value == other.Value
        if isinstance(other, int):
            return self.Value == other
        return False

class Enum:
    def __init__(self, name: str, items: Dict[str, int] = None):
        self._name = name
        self._items = {}
        if items:
            for k, v in items.items():
                self._items[k] = EnumItem(k, v)

    def __getattr__(self, name):
        if name in self._items:
            return self._items[name]
        return EnumItem(name, hash(name) % 100000)

    def __repr__(self):
        return f"Enum.{self._name}"

    @staticmethod
    def __getitem__(key):
        return Enum(str(key))
