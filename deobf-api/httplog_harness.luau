local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

local targetFile = process.args[1]
local outFile = process.args[2] or "captured.lua"
local stringsFile = process.args[4]

if not fs.isFile(targetFile) then
	error("Target file not found: " .. targetFile)
end

local input = fs.readFile(targetFile)

local decoded_strings = {}
if stringsFile and #stringsFile > 0 and fs.isFile(stringsFile) then
	local chunk, load_err = load(fs.readFile(stringsFile))
	if chunk then
		local ok, data = pcall(chunk)
		if ok and type(data) == "table" then
			decoded_strings = data
		end
	end
end

local r = {}
local c = 0

local function _25ms(var)
	if type(var) == "string" then
		c = c + 1
		r[c] = var
	end
	return var
end

local function _spy_make(name)
	local t = {}
	local mt = {}
	mt.__type = function() return "userdata" end
	mt.__tostring = function() return name end
	mt.__len = function() return 0 end
	mt.__add = function() return 0 end
	mt.__sub = function() return 0 end
	mt.__mul = function() return 0 end
	mt.__div = function() return 0 end
	mt.__mod = function() return 0 end
	mt.__unm = function() return 0 end
	mt.__concat = function(a, b) return tostring(a) .. tostring(b) end
	mt.__lt = function() return false end
	mt.__le = function() return false end
	mt.__eq = function() return false end
	mt.__index = function(self, k)
		return _spy_make(name .. "." .. tostring(k))
	end
	mt.__newindex = function(self, k, v)
		if type(v) == "string" then
			_25ms(v)
		end
	end
	mt.__call = function(self, ...)
		return _spy_make(name .. "(...)")
	end
	setmetatable(t, mt)
	return t
end

local _bit32 = rawget(_G, "bit32")
if not _bit32 then
	_bit32 = {
		bxor = function(a, b)
			local r, m = 0, 1
			while a > 0 or b > 0 do
				if (a % 2) ~= (b % 2) then r = r + m end
				a = math.floor(a / 2)
				b = math.floor(b / 2)
				m = m * 2
			end
			return r
		end,
		band = function(a, b)
			local r, m = 0, 1
			while a > 0 and b > 0 do
				if (a % 2) + (b % 2) == 2 then r = r + m end
				a = math.floor(a / 2)
				b = math.floor(b / 2)
				m = m * 2
			end
			return r
		end,
		bor = function(a, b)
			local r, m = 0, 1
			while a > 0 or b > 0 do
				if (a % 2) + (b % 2) > 0 then r = r + m end
				a = math.floor(a / 2)
				b = math.floor(b / 2)
				m = m * 2
			end
			return r
		end,
		lshift = function(v, n) return math.floor(v * (2 ^ n)) % 4294967296 end,
		rshift = function(v, n) return math.floor(v / (2 ^ n)) end,
		arshift = function(v, n) return math.floor(v / (2 ^ n)) end,
		bnot = function(a) return _bit32.bxor(a, 4294967295) end,
		rol = function(a, n) return _bit32.bor(_bit32.lshift(a, n), _bit32.rshift(a, 32 - n)) end,
		ror = function(a, n) return _bit32.bor(_bit32.rshift(a, n), _bit32.lshift(a, 32 - n)) end,
		btest = function(a, b) return _bit32.band(a, b) ~= 0 end,
		extract = function(a, f, w) return _bit32.band(_bit32.rshift(a, f), 2 ^ w - 1) end,
		replace = function(a, v, f, w)
			local mask = _bit32.lshift(2 ^ w - 1, f)
			return _bit32.bor(_bit32.band(a, _bit32.bnot(mask)), _bit32.lshift(v, f))
		end,
	}
end

local _unpack = table.unpack or unpack

local _captured_lines = {}

local function _log_line(msg)
	_25ms(msg)
	_captured_lines[#_captured_lines + 1] = msg
end

local function _wrap_binop(op)
	return function(a, b)
		local a_str = type(a) == "string" and string.format("%q", a) or tostring(a)
		local b_str = type(b) == "string" and string.format("%q", b) or tostring(b)
		local expr = "(" .. a_str .. " " .. op .. " " .. b_str .. ")"
		_log_line(expr)
		local fn, err = load("return " .. expr)
		if fn then
			local ok, result = pcall(fn)
			if ok then return result end
		end
		return a and b
	end
end

local function _wrap_unop(op)
	return function(a)
		local a_str = type(a) == "string" and string.format("%q", a) or tostring(a)
		local expr = "(" .. op .. a_str .. ")"
		_log_line(expr)
		local fn, err = load("return " .. expr)
		if fn then
			local ok, result = pcall(fn)
			if ok then return result end
		end
		return a
	end
end

local _cenv = {}
setmetatable(_cenv, { __index = _G })

_cenv._25ms = _25ms
_cenv._raw_add = _wrap_binop("+")
_cenv._raw_sub = _wrap_binop("-")
_cenv._raw_mul = _wrap_binop("*")
_cenv._raw_div = _wrap_binop("/")
_cenv._raw_concat = _wrap_binop("..")
_cenv._raw_eq = _wrap_binop("==")
_cenv._raw_lt = _wrap_binop("<")
_cenv._raw_le = _wrap_binop("<=")
_cenv._raw_gt = _wrap_binop(">")
_cenv._raw_ge = _wrap_binop(">=")
_cenv._raw_not = _wrap_unop("not ")
_cenv._raw_len = _wrap_unop("#")

_cenv._log_assign = function(name, value)
	local val_str = type(value) == "string" and string.format("%q", value) or tostring(value)
	_log_line(name .. " = " .. val_str)
	return value
end

_cenv._log_call = function(func_name, ...)
	local args = { ... }
	local arg_strs = {}
	for i, v in ipairs(args) do
		arg_strs[i] = type(v) == "string" and string.format("%q", v) or tostring(v)
	end
	_log_line(func_name .. "(" .. table.concat(arg_strs, ", ") .. ")")
	return ...
end

_cenv.pcall = function(fn, ...)
	local results = {pcall(fn, ...)}
	if not results[1] then
		local err = results[2]
		local trace = debug.traceback("", 2)
		_25ms("[Error] " .. tostring(err))
		_25ms("[Trace] " .. trace)
	end
	return _unpack(results)
end

_cenv.xpcall = xpcall or function(f, errh, ...) return pcall(f, ...) end
_cenv.getfenv = function(lvl)
	return _cenv
end
_cenv.setfenv = function(f, e)
	return f
end
_cenv.loadstring = function(src, b)
	if type(src) == "string" then
		_25ms(src)
		_25ms("[Payload captured: " .. #src .. " bytes]")
		local fn, err = luau.load(src, {
			debugName = type(b) == "string" and b or "=(load)",
			environment = _cenv,
			injectGlobals = true,
		})
		if fn then
			local ok, result = pcall(fn)
			if ok and type(result) == "string" and #result > 10 then
				_25ms(result)
				_25ms("[Payload returned: " .. #result .. " bytes]")
			elseif ok and type(result) == "function" then
				local ok2, result2 = pcall(result)
				if ok2 and type(result2) == "string" and #result2 > 10 then
					_25ms(result2)
					_25ms("[Payload returned: " .. #result2 .. " bytes]")
				end
			end
			local output = table.concat(r, "\n")
			fs.writeFile(outFile, output)
			return fn
		end
		local output = table.concat(r, "\n")
		fs.writeFile(outFile, output)
		return function() end, nil
	end
	return nil, "source must be a string"
end
_cenv.load = _cenv.loadstring

_cenv.select = select or function(n, ...)
	if n == "#" then return select("#", ...) end
	local args = {...}
	local result = {}
	for i = n, #args do
		result[#result + 1] = args[i]
	end
	return _unpack(result)
end
_cenv.unpack = _unpack
_cenv.setmetatable = setmetatable
_cenv.getmetatable = getmetatable
_cenv.rawequal = rawequal or function(a, b) return a == b end
_cenv.rawget = rawget or function(t, k) return t[k] end
_cenv.rawset = rawset or function(t, k, v) t[k] = v; return t end
_cenv.next = next
_cenv.ipairs = ipairs
_cenv.pairs = pairs
_cenv.error = error
_cenv.assert = assert
_cenv.collectgarbage = collectgarbage or function() return 0 end
_cenv.math = math
_cenv.string = string
_cenv.table = table
_cenv.bit32 = _bit32
_cenv.bit = _bit32
_cenv.newproxy = function(addmeta)
	local p = {}
	if addmeta then setmetatable(p, {}) end
	return p
end
_cenv.typeof = function(obj)
	local mt = getmetatable(obj)
	if mt and mt.__type and mt.__type() == "userdata" then
		return "userdata"
	end
	return type(obj)
end

_cenv.coroutine = coroutine or {
	create = function(f) return { __func = f } end,
	resume = function(co, ...)
		if type(co) == "table" and co.__func then
			return pcall(co.__func, ...)
		end
		return pcall(co, ...)
	end,
	wrap = function(f)
		return function(...)
			return pcall(f, ...)
		end
	end,
	yield = function() end,
	status = function() return "suspended" end,
	running = function() return nil end,
	isyieldable = function() return true end,
	close = function() end,
}

_cenv.os = {
	time = function() return 0 end,
	clock = function() return 0 end,
	date = function() return "" end,
	difftime = function() return 0 end,
	execute = function() return nil end,
	exit = function() end,
	getenv = function() return nil end,
	remove = function() return nil end,
	rename = function() return nil end,
	setlocale = function() return "" end,
	tmpname = function() return "" end,
}

_cenv.require = function(id)
	if id == "@lune/fs" then return fs end
	if id == "@lune/process" then return process end
	if id == "@lune/luau" then return luau end
	return _spy_make("require." .. tostring(id))
end

_cenv.script_key = "c4ce76cd36f2afee4dcee7e87576e5fa"

_cenv.game = _spy_make("game")
_cenv.workspace = _spy_make("workspace")
_cenv.script = _spy_make("script")
_cenv.shared = {}
_cenv._G = _cenv
_cenv._ENV = _cenv
_cenv._VERSION = "Luau"

_cenv.CFrame = _spy_make("CFrame")
_cenv.Vector3 = _spy_make("Vector3")
_cenv.Vector2 = _spy_make("Vector2")
_cenv.Color3 = _spy_make("Color3")
_cenv.UDim2 = _spy_make("UDim2")
_cenv.UDim = _spy_make("UDim")
_cenv.Instance = _spy_make("Instance")
_cenv.Drawing = _spy_make("Drawing")
_cenv.Ray = _spy_make("Ray")
_cenv.BrickColor = _spy_make("BrickColor")
_cenv.Region3 = _spy_make("Region3")
_cenv.TweenInfo = _spy_make("TweenInfo")
_cenv.Region3int16 = _spy_make("Region3int16")
_cenv.NumberRange = _spy_make("NumberRange")
_cenv.NumberSequence = _spy_make("NumberSequence")
_cenv.NumberSequenceKeypoint = _spy_make("NumberSequenceKeypoint")
_cenv.PathWaypoint = _spy_make("PathWaypoint")
_cenv.PhysicalProperties = _spy_make("PhysicalProperties")
_cenv.Random = _spy_make("Random")
_cenv.RaycastParams = _spy_make("RaycastParams")
_cenv.RaycastResult = _spy_make("RaycastResult")
_cenv.Rect = _spy_make("Rect")
_cenv.Axes = _spy_make("Axes")
_cenv.Faces = _spy_make("Faces")
_cenv.CatalogSearchParams = _spy_make("CatalogSearchParams")
_cenv.DateTime = _spy_make("DateTime")
_cenv.DockWidgetPluginGuiInfo = _spy_make("DockWidgetPluginGuiInfo")
_cenv.Font = _spy_make("Font")
_cenv.OverlapParams = _spy_make("OverlapParams")
_cenv.Secret = _spy_make("Secret")
_cenv.SharedTable = _spy_make("SharedTable")
_cenv.Buffer = _spy_make("Buffer")

_cenv.task = {
	wait = function() return 1 end,
	spawn = function(f) pcall(f) end,
	defer = function(f) pcall(f) end,
	delay = function(t, f) pcall(f) end,
	cancel = function() end,
}
_cenv.wait = function() return 1 end
_cenv.spawn = function(f) pcall(f) end
_cenv.delay = function(t, f) pcall(f) end
_cenv.tick = function() return 0 end
_cenv.time = function() return 0 end
_cenv.elapsedTime = function() return 0 end

_cenv.plugin = _spy_make("plugin")
_cenv.PluginManager = _spy_make("PluginManager")
_cenv.settings = _spy_make("settings")
_cenv.stats = _spy_make("stats")

local function _make_enum(name)
	local e = _spy_make(name)
	local mt = getmetatable(e)
	mt.__index = function(t, k)
		return _spy_make(name .. "." .. k)
	end
	return e
end

_cenv.Enum = setmetatable({}, {
	__index = function(t, k)
		return _make_enum("Enum." .. k)
	end,
	__tostring = function() return "Enum" end,
})

_cenv.getgenv = function() return _cenv end
_cenv.getrenv = function() return _G end
_cenv.getsenv = function() return _cenv end
_cenv.getthreadidentity = function() return 8 end
_cenv.setthreadidentity = function(n) end
_cenv.getthreadcontext = function() return 8 end
_cenv.setthreadcontext = function(n) end
_cenv.checkcaller = function() return true end
_cenv.identifyexecutor = function() return "Synapse X", "2.0" end
_cenv.getexecutorname = function() return "Synapse X" end
_cenv.getexecutorversion = function() return "2.0" end
_cenv.getexecutorbuild = function() return "stable" end

_cenv.getrawmetatable = function(t) return getmetatable(t) end
_cenv.setrawmetatable = function(t, m) return setmetatable(t, m) end
_cenv.gethui = function() return _spy_make("HUI") end
_cenv.gethiddenui = function() return _spy_make("HiddenUI") end
_cenv.getnilinstances = function() return {} end
_cenv.getinstances = function() return {} end
_cenv.getgc = function() return {} end
_cenv.getreg = function() return {} end
_cenv.getloadedmodules = function() return {} end
_cenv.getconnections = function() return {} end
_cenv.getscripts = function() return {} end
_cenv.getrunningscripts = function() return {} end
_cenv.getscripthash = function() return "hash" end
_cenv.getcallbackvalue = function() return nil end

_cenv.firesignal = function() end
_cenv.fireclickdetector = function() end
_cenv.fireproximityprompt = function() end
_cenv.firetouchinterest = function() end
_cenv.setreadonly = function() end
_cenv.isreadonly = function() return false end
_cenv.makewriteable = function() end
_cenv.iswriteable = function() return true end

_cenv.hookfunction = function(f, h) return f end
_cenv.hookmetamethod = function(o, m, f) return function() end end
_cenv.newcclosure = function(f) return f end
_cenv.clonefunction = function(f) return f end
_cenv.iscclosure = function() return false end
_cenv.islclosure = function() return true end
_cenv.isourclosure = function() return false end
_cenv.checkclosure = function() return true end
_cenv.restorefunction = function(f) end
_cenv.clonefunc = function(f) return f end
_cenv.replaceclosure = function(f, r) end
_cenv.getfunctionaddress = function(f) return 0 end
_cenv.getfunctionsource = function(f) return "" end

_cenv.getnamecallmethod = function() return "" end
_cenv.setnamecallmethod = function(m) end
_cenv.isnetworkowner = function() return true end

_cenv.gethiddenprop = function() return nil end
_cenv.sethiddenprop = function() end
_cenv.gethiddenprops = function() return {} end
_cenv.getproperties = function() return {} end
_cenv.getattributes = function() return {} end
_cenv.setattribute = function() end

_cenv.getcustomasset = function(s) return "content" end
_cenv.getsynasset = function(s) return "content" end

_cenv.httpget = function(u) return "" end
_cenv.httpspost = function(u, d) return "" end
_cenv.request = function(o)
	_25ms(tostring(o.Url))
	return {
		StatusCode = 200,
		Body = "--REMOTE_PAYLOAD",
		Headers = {},
		Success = true,
		StatusMessage = "OK",
	}
end
_cenv.http_request = _cenv.request
_cenv.HttpGet = _cenv.httpget
_cenv.HttpPost = _cenv.httpspost
_cenv.HttpGetAsync = _cenv.httpget
_cenv.HttpPostAsync = _cenv.httpspost

_cenv.readfile = function(f) return "" end
_cenv.writefile = function(f, c) end
_cenv.appendfile = function(f, c) end
_cenv.loadfile = function(f) return function() end end
_cenv.isfile = function() return false end
_cenv.isfolder = function() return false end
_cenv.makefolder = function() end
_cenv.delfolder = function() end
_cenv.delfile = function() end
_cenv.listfiles = function() return {} end
_cenv.readfileasync = function(f) return "" end
_cenv.writefileasync = function(f, c) end

_cenv.rconsoleprint = function() end
_cenv.rconsoleinfo = function() end
_cenv.rconsolewarn = function() end
_cenv.rconsoleerr = function() end
_cenv.rconsoleclear = function() end
_cenv.rconsolename = function() end
_cenv.rconsoleinput = function() return "" end
_cenv.rconsolesettitle = function() end

_cenv.mouse1click = function() end
_cenv.mouse1press = function() end
_cenv.mouse1release = function() end
_cenv.mouse2click = function() end
_cenv.mouse2press = function() end
_cenv.mouse2release = function() end
_cenv.mousemoveabs = function() end
_cenv.mousemoverel = function() end
_cenv.keypress = function() end
_cenv.keyrelease = function() end
_cenv.scrollwheel = function() end

_cenv.iswindowactive = function() return true end
_cenv.isactive = function() return true end
_cenv.setclipboard = function(s) end
_cenv.toclipboard = function(s) end
_cenv.getclipboard = function() return "" end

_cenv.setfpscap = function(c) end
_cenv.getfpscap = function() return 240 end
_cenv.getping = function() return 50 end
_cenv.setmaxmemory = function(m) end

_cenv.messagebox = function(t, m, b) return 1 end
_cenv.MessageBox = function(t, m, b) return 1 end

_cenv.websocket = {
	connect = function() return _spy_make("WebSocket") end,
}

_cenv.crypt = {
	encrypt = function(d) return d end,
	decrypt = function(d) return d end,
	hash = function(d) return "hash" end,
	generatekey = function() return "key" end,
	generatebytes = function(n) return string.rep("x", n) end,
	base64encode = function(d) return d end,
	base64decode = function(d) return d end,
	base64 = { encode = function(d) return d end, decode = function(d) return d end },
	custom = { encrypt = function(d) return d end, decrypt = function(d) return d end },
}

local function _executor_api()
	return {
		request = _cenv.request,
		crypt = _cenv.crypt,
		queue_on_teleport = function() end,
		protect_gui = function() end,
		secure_call = function(f, ...) return f(...) end,
		write_clipboard = function(s) end,
		is_beta = function() return false end,
		set_fps_cap = function(c) end,
		get_fps_cap = function() return 240 end,
		set_fflag = function() end,
		websocket = {
			connect = function() return _spy_make("WebSocket") end,
		},
		custom_theme = function() end,
		set_title = function(t) end,
		open_dll = function() return _spy_make("DLL") end,
		is_injected = function() return true end,
		is_loaded = function() return true end,
		get_script = function() return "" end,
		save_cfg = function() end,
		load_cfg = function() return {} end,
		set_watermark = function() end,
		get_watermark = function() return "LINO" end,
		set_visibility = function() end,
		get_visibility = function() return true end,
		uninject = function() end,
		inject = function() end,
	}
end

_cenv.syn = _executor_api()
_cenv.krnl = _executor_api()
_cenv.fluxus = _executor_api()
_cenv.sw = _executor_api()
_cenv.electron = _executor_api()
_cenv.comet = _executor_api()
_cenv.codex = _executor_api()
_cenv.scriptware = _executor_api()
_cenv.nonsense_diamond = _executor_api()
_cenv.sentinel = _executor_api()
_cenv.vega_x = _executor_api()
_cenv.valyse = _executor_api()
_cenv.trigon = _executor_api()
_cenv.aris = _executor_api()
_cenv.nexus = _executor_api()
_cenv.wave = _executor_api()
_cenv.zorara = _executor_api()
_cenv.sirius = _executor_api()
_cenv.delta = _executor_api()
_cenv.ev0n = _executor_api()
_cenv.kiro = _executor_api()
_cenv.hydrogen = _executor_api()
_cenv.solara = _executor_api()
_cenv.jjsploit = _executor_api()
_cenv.xenon = _executor_api()
_cenv.synapse = _executor_api()
_cenv.calamari = _executor_api()
_cenv.mars = _executor_api()
_cenv.oxygen_u = _executor_api()
_cenv.rain = _executor_api()
_cenv.ganymede = _executor_api()
_cenv.velvet = _executor_api()
_cenv.frostbite = _executor_api()
_cenv.nihon = _executor_api()
_cenv.facet = _executor_api()
_cenv.octohook = _executor_api()
_cenv.furky = _executor_api()
_cenv.spectrum = _executor_api()
_cenv.athlos = _executor_api()
_cenv.prelete = _executor_api()
_cenv.loki = _executor_api()
_cenv.balloons = _executor_api()
_cenv.domainx = _executor_api()
_cenv.doggo = _executor_api()
_cenv.viper = _executor_api()
_cenv.aurora = _executor_api()
_cenv.cerberus = _executor_api()
_cenv.wisteria = _executor_api()
_cenv.asshurt = _executor_api()
_cenv.outerlib = _executor_api()
_cenv.queen = _executor_api()
_cenv.swift = _executor_api()
_cenv.vandal = _executor_api()
_cenv.ishtar = _executor_api()
_cenv.nightshade = _executor_api()
_cenv.winterblade = _executor_api()
_cenv.luna = _executor_api()
_cenv.rogue = _executor_api()
_cenv.sova = _executor_api()
_cenv.azrael = _executor_api()
_cenv.kaiser = _executor_api()
_cenv.zaika = _executor_api()
_cenv.cypher = _executor_api()
_cenv.seraph = _executor_api()
_cenv.kage = _executor_api()
_cenv.orcus = _executor_api()
_cenv.nightcore = _executor_api()
_cenv.cherry = _executor_api()
_cenv.ashley = _executor_api()
_cenv.coco_z = _executor_api()
_cenv.elysian = _executor_api()
_cenv.phantom = _executor_api()
_cenv.tempest = _executor_api()
_cenv.fracture = _executor_api()
_cenv.graviton = _executor_api()
_cenv.necron = _executor_api()
_cenv.diablo = _executor_api()
_cenv.nexure = _executor_api()
_cenv.intriga = _executor_api()
_cenv.saiyan = _executor_api()
_cenv.hyperion = _executor_api()
_cenv.akira = _executor_api()
_cenv.artemis = _executor_api()
_cenv.astral = _executor_api()
_cenv.atlas = _executor_api()
_cenv.eva = _executor_api()
_cenv.genji = _executor_api()
_cenv.ichigo = _executor_api()
_cenv.kura = _executor_api()
_cenv.lin = _executor_api()
_cenv.narco = _executor_api()
_cenv.neo = _executor_api()
_cenv.nox = _executor_api()
_cenv.odin = _executor_api()
_cenv.osiris = _executor_api()
_cenv.ovis = _executor_api()
_cenv.panda = _executor_api()
_cenv.phoenix = _executor_api()
_cenv.raikou = _executor_api()
_cenv.reyna = _executor_api()
_cenv.ruby = _executor_api()
_cenv.ryuga = _executor_api()
_cenv.selene = _executor_api()
_cenv.shiro = _executor_api()
_cenv.silver = _executor_api()
_cenv.slayer = _executor_api()
_cenv.solstice = _executor_api()
_cenv.sparta = _executor_api()
_cenv.stigma = _executor_api()
_cenv.synergy = _executor_api()
_cenv.taiga = _executor_api()
_cenv.tokyo = _executor_api()
_cenv.vector = _executor_api()
_cenv.veno = _executor_api()
_cenv.void = _executor_api()
_cenv.wolf = _executor_api()
_cenv.xen = _executor_api()
_cenv.yama = _executor_api()
_cenv.zero = _executor_api()
_cenv.zion = _executor_api()
_cenv.eulen = _executor_api()
_cenv.menu = _executor_api()
_cenv.lynx = _executor_api()
_cenv.riot = _executor_api()
_cenv.catalyst = _executor_api()
_cenv.pluto = _executor_api()
_cenv.aurora_x = _executor_api()
_cenv.sirhurt = _executor_api()
_cenv.proxo = _executor_api()
_cenv.furk_os = _executor_api()
_cenv.shark = _executor_api()

_cenv.debug = {
	getinfo = function() return { source = "mock", short_src = "mock", func = function() end, currentline = 1, linedefined = 1, lastlinedefined = 1, nups = 0, nparams = 0, isvararg = 0, istailcall = 0, name = "mock", namewhat = "", what = "Lua" } end,
	getconstants = function() return {} end,
	getconstant = function() return nil end,
	setconstant = function() end,
	getupvalues = function() return {} end,
	getupvalue = function() return nil end,
	setupvalue = function() end,
	getprotos = function() return {} end,
	getproto = function() return nil end,
	getstack = function() return {} end,
	setstack = function() end,
	getregistry = function() return {} end,
	getmetatable = function(t) return getmetatable(t) end,
	setmetatable = function(t, m) return setmetatable(t, m) end,
	profilebegin = function() end,
	profileend = function() end,
	traceback = function(msg, level)
		return "[string \"chunk\"]:1: in function <chunk:1>"
	end,
	sethook = function() end,
	gethook = function() return nil, "", 0 end,
	getlocal = function() return nil end,
	setlocal = function() end,
	getfenv = function() return _cenv end,
	setfenv = function() end,
}

_cenv.drawing = _spy_make("Drawing")

if #decoded_strings > 0 then
	_cenv.R = setmetatable({}, {
		__index = function(t, k)
			local idx = tonumber(k)
			if idx and idx >= 1 and idx <= #decoded_strings then
				return decoded_strings[idx]
			end
			for i, s in ipairs(decoded_strings) do
				if s == k then
					return _G[s] or _cenv[s]
				end
			end
			return nil
		end
	})
	_cenv.EncStr = _cenv.R
	_cenv.table = setmetatable({}, {
		__index = function(t, k)
			local real_val = rawget(table, k) or rawget(_G, k)
			if real_val ~= nil then
				return real_val
			end
			for i, s in ipairs(decoded_strings) do
				if s == k then
					local resolved = _G[s] or _cenv[s]
					if resolved ~= nil then
						return resolved
					end
				end
			end
			return _spy_make("table." .. tostring(k))
		end,
		__newindex = function(t, k, v)
			rawset(table, k, v)
		end,
	})
end

local _orig_table_concat = table.concat
table.concat = function(t, sep, i, j)
	local r = _orig_table_concat(t, sep, i, j)
	if type(r) == "string" and #r > 5 then _25ms(r) end
	return r
end

local _orig_string_char = string.char
string.char = function(...)
	local r = _orig_string_char(...)
	if select("#", ...) >= 3 then _25ms(r) end
	return r
end

local loadable_input = input
local ret_pos = loadable_input:find("return")
if ret_pos then
	local after_ret = loadable_input:sub(ret_pos + 6)
	local paren_pos = after_ret:find("%(")
	if paren_pos then
		loadable_input = after_ret:sub(paren_pos)
	end
end

local chunk, err = luau.load(loadable_input, {
	debugName = "script",
	environment = _cenv,
	injectGlobals = true,
})
if err then
	fs.writeFile(outFile, "-- [ERROR] Compile: " .. err)
	return
end

local instruction_count = 0
local hook_active = false

local success, result = pcall(chunk)

if not success then
	c = c + 1
	local trace = debug.traceback("", 2)
	r[c] = "[Error] " .. tostring(result) .. "\n[Trace] " .. trace .. "\n[Harness] executed " .. instruction_count .. " instructions before failure"
end

local output_lines = {}
for _, line in ipairs(_captured_lines) do
	output_lines[#output_lines + 1] = line
end

if success then
	_25ms("[Harness] executed " .. instruction_count .. " instructions")
end

if #_captured_lines > 0 and #r > 0 then
	output_lines[#output_lines + 1] = ""
end

for _, raw in ipairs(r) do
	output_lines[#output_lines + 1] = raw
end

local output
if #output_lines == 0 and #r == 0 then
	output = "[Harness] No output captured. success=" .. tostring(success) .. " result_type=" .. type(result)
	if result ~= nil then
		local preview = tostring(result):sub(1, 500)
		output = output .. " result_preview=" .. preview
	end
	output = output .. " instructions=" .. instruction_count
else
	output = table.concat(output_lines, "\n")
end

fs.writeFile(outFile, output)
