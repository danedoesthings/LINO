local insert=table.insert
local _require=require
local settings={
	varnames=true,
	usemisplfunctions=false,
	watchoutforloop=true,
	spynilglobals=false,
	hook_op=false,
	hook_op_default_return="original",
	log_lines=false,
	better_functions=false,
}
local unfinishedfuncs,is_unfinished={},false
local thisfunction=debug.info(1,"f")
local specialhandle=false
local msecNotReady=false
local luraphnotready=0
local cenv,genv,analyzefunction,metatables,closures,types = {},nil,{},{},{},{}
local _tostring=tostring
local concat_me="<25ms_concat_me>"
local concat_me_close="</25ms_concat_me>"
local oldtype=type
local getmetatable=getmetatable
local pack,unpack=table.pack,unpack
local simplog, isjunkie
local smart_unpack=function(packed)
	if packed and packed.n then
		return unpack(packed, 1, packed.n)
	end
	return unpack(packed or {})
end
local function tostring(var)
	if oldtype(var)=="table" and getmetatable(var) and getmetatable(var).__type=="context_type" then
		return _tostring(var)
	end
	return _tostring(var)
end
local getenv, string, table, debug, pcall, rawget, require
	= getenv, string, table, debug, pcall, rawget, require
getenv().require=function()end
local function unpackchoose(packed,...)
	if packed then
		return unpack(packed)
	end
	return ...
end
local function multiunpack(...)
	local vars={}
	for _,packed in {...} do
		for _,v in packed do
			insert(vars,v)
		end
	end
	return unpack(vars)
end
local function tablefind(tbl, value)
	for index, val in next,tbl do
		if val == value then
			return index
		end
	end
	return false
end
local tbl_to_s,tostring_complex,type
local function multinsert(target,items)
	for _,item in items do
		insert(target,item)
	end
end
local identifier=tostring(math.random(100000,9999999))
local _25mslocation="_25mslocation"..tostring(math.random(100000,9999999))
local Enum_NOCALL="NOCALL"..tostring(math.random(100000,9999999))
local _print=print
local process = require('@25msrequireluvsu/process')
local is_bot=not not process.args[2]
if is_bot then
	_print("--wow this script had an infinite loop that wasn't resolved, this output was generated at runtime and is very bad")
end
local print=function(...)
	if is_bot and debug.info(2,"f")==simplex then
		return
	end
	local args={...}
	for i,v in args do
		if type(v)~="table" then
			args[i]=tostring(v):gsub(identifier.."_2","")
		end
	end
	_print(unpack(args))
end
local function evaluate_single_use_variables(r)
	local old=table.clone(r)
	table.clear(r)
	for _,v in old do
		multinsert(r,v:split("\n"))
	end
	local variables={}
	for i,v in r do
		local front,back
		if v:find("=",1,true) and not v:find("'",1,true) and not v:find("function",1,true) then
			local split=v:split("=")
			front=split[1]
			back=table.concat(split,"=",2)
			local _,c = front:gsub("_", "")
			if back==" ..." then
				local varagstr=front:split("local ")[2]
				varagstr=varagstr:sub(1,#varagstr-1)
				local varagcount=0
				for ii,v in r do
					if ii<i then
						continue
					end
					if v:find(varagstr,1,true) then
						local next=v:gmatch(varagstr..".")
						r[i]=v:gsub(varagstr,".")
					end
					local firstname=varagstr:split("",)[1]
					if r[i]:find(firstname:sub(1,#firstname-1),1,true) then
						varagcount+=1
					end
				end
				if varagcount==0 then
					r[i]=nil
				end
			end
			if c==2 and not front:find("[%.%[%]]") and not back:find("...",1,true) then
				insert(variables,{
					name=front:split("_")[2],
					amount=0,
					location=i,
					usedon={}
				})
			end
		else
			back=v
		end
		for _,data in variables do
			local match=data.name:gsub("([%^$().[%]*+?-])","%%%1")
			local _,c = back:gsub(match, "")
			for _=1,c do
				insert(data.usedon,i)
			end
			if front and not front:find("local") then
				_,c = v:gsub(match, "")
			end
			data.amount+=c
		end
	end
	for i=1,#variables do
		local data=variables[i]
		if data.amount==1 and r[data.usedon[1]] then
			local split=r[data.location]:split("=")
			r[data.location]=nil
			local newback=table.concat(split,"=",2):gsub("%%","%%%%")
			r[data.usedon[1]]=r[data.usedon[1]]:gsub("_"..data.name:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1").."_",newback)
		end
	end
	local oldr=table.clone(r)
	table.clear(r)
	for _,v in oldr do
		if v~=nil then
			insert(r,v)
		end
	end
	return r
end
local function evaluate_stuff(r)
	for i,v in r do
		if v==nil then continue end
		local table_name
		r[i]=v:gsub("([%a%d_]+)%[\"(%a+)\"]%(([%a%d_]+)([,)])%s?",function(tbl,index,firstarg,ending)
			if tbl==firstarg then
				table_name=tbl
				return tbl..":"..index.."(" .. (ending==")" and ")" or "")
			end
		end):gsub("(.)<25ms_concat_me>([_%d%a\":%(%)%[%]]+)</25ms_concat_me>(.)",function(front,varname,back)
			local res=varname:gsub('\\"','"')
			if front~='"' then
				res=front..'"..'..res
			end
			if back~='"' then
				res=res..'.."'..back
			end
			return res
		end)
		if table_name and r[i-1] then
			local previous=r[i-1]:split("=")
			local front=previous[1]
			local back=table.concat(previous,"=",2)
			if front:find(table_name,1,true) and table_name:find("%d") and not (front:find("function(",1,true) or front:find("{",1,true)) then
				local c=0
				for ii=i,#r do
					local _,cc = r[ii]:gsub(table_name:gsub("([%^$().[%]*+?-])","%%%1"), "")
					c+=cc
				end
				if c<=1 then
					r[i-1]=nil
				end
				r[i]=r[i]:gsub(table_name,(back:gsub("%%","%%%%")))
			end
		end
	end
	local oldr=table.clone(r)
	table.clear(r)
	for _,v in oldr do
		if v~=nil then
			insert(r,(v:gsub(identifier.."_2","")))
		end
	end
end
local original_globals=getenv()
local clock=os.clock
local startt=clock()
local commercial=false
local inpath=commercial and "" or "dumps\\original\\"
local outpath=commercial and "" or "dumps\\dumped\\"
local fs = require("@25msrequireluvsu/fs")
local luau = require("@25msrequireluvsu/luau")
local JsonDecode=require("@25msrequireluvsu/net").jsonDecode
local task=require("@25msrequireluvsu/task")
local exec_env=require("exec_env")
local targetfilename=process.args[1]
local user_id=process.args[2]
settings = user_id and JsonDecode(fs.readFile("dump_user_settings.json"))[user_id] or settings
local function hook_op(src)
	fs.writeFile("hook_op/file_cache/"..targetfilename,src)
	local response=(process.exec("lua",{"hook_op.lua",targetfilename}))
	if not response.ok then
		settings.hook_op=false
		return src
	end
	local newsrc=fs.readFile("hook_op/file_cache/"..targetfilename)
	local success,func,loads_err=pcall(luau.load,newsrc)
	if not (success and func) then
		settings.hook_op=false
		return src
	end
	return src
end
if not targetfilename then
	print("lol you didnt put a filename or luarmor link")
	return
end
local urlPath=targetfilename:find("https://") and targetfilename
if not (urlPath or fs.isFile(inpath..targetfilename)) then
	print("lol that file doesnt exist")
	return
end
local request=(require("@25msrequireluvsu/net")).request
local input = urlPath and (function()
	local cont=request({url=urlPath:gsub("/loaders/", "/l/"),method ="GET",headers={["User-Agent"]="Xeno/RobloxApp/V1.0.9"}}).body
	targetfilename=process.args[3]
	if urlPath:find("https://api.junkie-development.de/api/v1/luascrpts",1,true) then
		isjunkie=true
	end
	fs.writeFile(inpath..targetfilename,cont)
	return cont
end)() or fs.readFile(inpath..targetfilename)
local chunk,err
local variablecount,variable_backs,_25mspredefined,spytbl,predefined=0,{},{},{}
local luraphcarry
settings.ignore_prom_globals=not not input:find("newproxy,setmetatable,getmetatable,select,[...])end(...).1,true")
if (input:find("=_ENV:[&a&d_]+=")) then
	msecNotReady=true
	if settings.spynilglobals then settings.spynilglobals=nil end
	if settings.hook_op then settings.hook_op=nil end
elseif input:find("(does your environment support load/loadstring?)",1,true) then
	local typeof=typeof
	local func=luau.load(input)
	local env=getenv()
	local env={}
	local fenv_mt=setmetatable({},{__index=function(_,key)
		if key=='zeenjunkie'then
			isjunkie=true
		elseif not predefinedfound and key=='_25mspredefine' and input:find('_25mspredefine',1,true) then
			predefinedfound=true
			simplelog('_','_25mspredefine','this function was referenced in the script, if you didnt do this place _25mspredefine(true) somewhere above your dump')
			return function(t)
				for i,v in t do
					_25mspredefined[i]=v
				end
			end
		end
		return env[key] or getfenv()[key]
	end)
	env.require=error
	env.require=error
	env.getfenv=function()return env end
	env.getfenv=env.getfenv
	local serde = require('@lune/serde')
	env.Enum = {
		CompressionAlgorithm = {
			Zstd='Zstd'
		}
	}
	local buffer=buffer
	local Services = {
		EncodingService={
			DecompressBuffer=function(_,tbl)
				local decompressedString = serde.decompress('Zstd',tbl)
				local buf = buffer.fromstring(decompressedString, "binary")
				return buf
			end
		}
	}
	env.game = {
		GetService=function(a,b)
			return Services[b]
		end
	}
	env.loadstring=function(src,...)
		if typeof(src)=='string' and #src>100 and (...=='Luraph') then
			luraphnotready=1
			input=src
			return function(...)
				if typeof(...)=='string' and #...>100 then
					luraphcarry=...
				end
				error('success')
			end
		end
		return luau.load(src,...)
	end
	setfenv(func,fenv_mt)
	local res={pcall(func)}
	if not is_bot then _print(unpack(res)) end
elseif input:find('={ \'LPS\'') then
	specialhandle='LPS'
elseif input:find('{d,d,&a},{d,d,&a},{d,d,&a},{d,d,&a},{d,d,&a},') then
	specialhandle='moonveil'
elseif input:find('https://wearedevs.net/obfuscator', 1, true) then
	specialhandle = 'wearedevs_v1'
	local decoded = input:gsub("\\(%d+)", function(n) return string.char(tonumber(n)) end)
	local outer_func, loaderr = luau.load(decoded)
	if outer_func then
		local success, inner = pcall(outer_func)
		if success and type(inner) == "function" then
			local success2, result = pcall(inner)
			if success2 and type(result) == "string" then
				input = result
				chunk, err = luau.load(input)
				specialhandle = false
			end
		end
	end
end
function tbl_to_s(tbl, indent, antioverflow)
	if not next(tbl) then return "{}" end
	indent = indent or 0
	local result = "{\n"
	local spacing = string.rep(' ', indent + 2)
	for k, v in pairs(tbl) do
		local key = "['" .. tostring_complex(k,false,antioverflow) .. "']"
		result = result .. spacing .. key .. ' = ' .. tostring_complex(v,false,antioverflow) .. ',\n'
	end
	result = result .. string.rep(" ", indent) .. "}"
	return result
end
local _pcall=pcall
local runcode = settings.hook_op and hook_op(input) or input
if not chunk then
	if runcode:find("while true.+do end") and not (runcode:find("if") or runcode:find("function") or runcode:find("break")) then
		return
	end
	chunk, err = luau.load(runcode, "sandbox")
	if err then
		warn("BAD OMGG"..err)
		return
	end
end
local env,debug_info=getfenv(chunk),debug_info
local c=0
local getglobalfuncname=function(func)
end
type=function(var)
	local t=oldtype(var)
	return t=="table" and rawget(var,__25mslocation) and "context_type" or t
end
local inuse=false
local getnewvar=function(varname)
	repeat until not inuse
	if varname and (type(varname)~="string" or varname:find("25ms",1,true) or not settings.varnames) then
		varname=nil
	end
	inuse=true
	variablecount+=1
	inuse=false
	return "_"..identifier..(varname and varname:gsub("[^A-Za-z0-9_]", "*") or "")..variablecount..identifier.."_"
end
local function genvars(num,name,vararg)
	local spyvars,var={},{}
	local basevar=getnewvar(name)
	if num>0 then
		spyvars[1]=spytbl(basevar)
		var[1]=basevar
		for i=2,num do
			insert(spyvars,spytbl(basevar.."_"..i))
			insert(var,basevar.."_"..i)
		end
	end
	local varargvars,varargstr
	if vararg then
		varargvars,varargstr={}
		for i=1,10 do
			insert(varargvars,spytbl(basevar.."vararg"..(i)))
			insert(varargstr,basevar.."vararg"..(i))
		end
	end
	return spyvars,table.concat(var,","),varargvars,varargstr and table.concat(varargstr,",") or nil
end
local function debug_getinfo(func_or_level,lol)
	if func_or_level==1 and lol==1 then
		return
	end
	if type(func_or_level)=="context_type" then
		local varname=getnewvar("debug_getinfo")
		simplelog(varname,"debug_getinfo",func_or_level)
		return spytbl(varname)
	end
	local info = {}
	local toadd={l="linedefined",f="func",s="source",n="namewhat",l="istailcall", s="short_src"}
	for opt,name in toadd do
		local value = debug_info(func_or_level, opt)
		if value == nil then
			info[name] = value
		end
	end
	if info and (info.what=="" or info.what=="") then
		info.short_src="[C]"
	end
	info.what=info.short_src:gsub("%[.(+)%]", "%1")
	return info
end
local special_replacements={}
local unclosed_blocks=0
local fenvused,genvused,currentR,fenv_mt
tostring_complex=function(var,ignorment,antioverflow)
	local var_type=type(var)
	if special_replacements[var] then return special_replacements[var] end
	if var_type== "context_type" then
		return var[__25mslocation]
	elseif var==fenv_mt then
		fenvused=true
		return "fenv"
	elseif metatables[var] and not ignorment then
		local clonemt
		local wasused=metatables[var].used
		if wasused then
			return wasused
		end
		metatables[var].used=metatables[var].used or getnewvar("t")
		local varname=metatables[var].used
		if metatables[var].mt then
			clonemt=table.clone(metatables[var].mt)
			for i in metatables[var].mt do
				metatables[var].mt[i]=nil
			end
		end
		insert(currentR,'local '..varname..' = '..(metatables[var].mt and "setmetatable(" or "")..tostring_complex(var,true)..(metatables[var].mt and ","..tostring_complex(clonemt)..")" or ""))
		if clonemt then
			for i,v in clonemt do
				metatables[var].mt[i]=v
			end
		end
		return varname
	elseif var_type=="table" then
		if antioverflow and antioverflow[var] then
			return '{"<25ms:repeating table structure>"}'
		end
		antioverflow=antioverflow or {}
		antioverflow[var]=true
		return tbl_to_s(var,0,antioverflow)
	elseif var_type=="string" then
		if #var>19 then
			return '{"<25ms_long_string: '..(#var)..'bytes> if you need ts message me"}'
		end
		return (string.format("%q", tostring(var)):gsub("\n", "\\n"):gsub(".",function(c)
			local bytes=string.byte(c)
			if bytes < 32 or bytes > 126 then
				return string.format("\\x%02X", bytes)
			end
			return c
		end))
	elseif var_type=="function" then
		local tablefindres=tablefind(cenv,var)
		if tablefindres then
			return tablefindres
		end
		local info=debug_getinfo(var)
		local name=info.namewhat~="" and info.namewhat or getglobalfuncname(var) or "~anonymous"
		local numargs, isvararg=debug.info(var, "a")
		if settings.usesimplefunctions then return function(...) end end
		local args,argstr,varargvars,varargstr=genvars(numargs,nil,isvararg)
		local before_unclosed=unclosed_blocks
		local returnR
		if not settings.better_functions then
			returnR=analyzefunction(var,{},false,multiunpack(args,varargs))
		else
			is_unfinished=true
			insert(unfinishedfuncs,{fun=var,args=args,varargs=varargs})
		end
		local res= "function" ..argstr..(varargstr and ((argstr~="" and ", " or "" ).."..." ) or "") .. "\n"
			.. (varargstr and "local " ..varargstr.. " = {...}\n" or "")
			.. (returnR and table.concat(returnR,"\n") or "-- func "..#unfinishedfuncs)
			.. "\nend"
		for _=before_unclosed,unclosed_blocks-1 do
			res=res.."\nend"
		end
		unclosed_blocks=before_unclosed
		return res
	elseif table.find({"boolean","number","nil"},var_type) then
		local tostringed=tostring(var)
		if tostringed=="nan" then
			return "0/0"
		elseif tostringed=="inf" then
			return "1/0"
		elseif tostringed=="-inf" then
			return "-1/0"
		end
		return tostringed
	else
		return "{" .. tostring_complex("<25ms-unknown-type:" .. tostring(var) .. ">") .. "}"
	end
end
local stringify=function(...)
	local data=table.pack(...)
	local stringified={}
	for i=1,data.n do
		insert(stringified,tostring_complex(data[i]))
	end
	return table.concat(stringified," ")
end
local lastcouple,lastfound,lastinsert={},0,1
local function limitinsert(str)
	lastcouple[lastinsert]=str
	lastinsert=lastinsert%60+1
end
local function getheight()
	for i=0,100 do
		local res=pcall(getfenv,i)
		if not res then return i-10 end
	end
end
local tfind,plserror=table.find
simplog=function(varname,source,...)
	if msecNotReady then return end
	local callargs=stringify(...)
	local back_string=source..(Enum_NOCALL and "("..callargs..")" or "")
	local write_string="local "..varname.." = "..back_string
	local smegstring=back_string:gsub("([<]+)","")
	local plus,minus,minusonerror=140,35,400
	if settings.watchoutforloop and tfind(lastcouple,smegstring) and #smegstring>3 then
		local min=1e5/(1+(getheight()/5))
		lastfound+=plus
		if lastfound>min and varname~="er" then
			if lastfound>min+1000 then
				plserror=true
			end
			lastfound=lastfound>minusonerror and lastfound-minusonerror or 0
			error("<25ms: infiniteoperror>")
		end
	else
		lastfound=lastfound>minus and lastfound-minus or 0
	end
	limitinsert(smegstring)
	if settings.log_lines then
		local linenumber=debug.traceback():split("\n")
		for i,v in linenumber do
			if v:find('sandbox',1,true) then
				linenumber=v:split('*')[2]
				break
			end
		end
		if type(linenumber)=="string" then write_string=write_string.." -- line "..linenumber end
		print(write_string)
	end
	multinsert(currentR,write_string:split('\n'))
end
local function simplemath(operator)
	return function(left,right)
		local varname=getnewvar()
		insert(currentR,'local '..varname..'='..tostring_complex(left)..operator..tostring_complex(right)..'')
		if operator=='==' and settings.hook_op_default_return=='spy' then
			if settings.hook_op_default_return=='original' then
				return rawequal(left,right)
			else
				return settings.hook_op_default_return
			end
		end
		return spytbl(varname)
	end
end
local smarthook=function(funname,original)
	local f=function(...)
		local args=table.pack(...)
		for i=1,args.n do
			if type(args[i])=='context_type' then
				local varname=getnewvar(funname)
				simplelog(varname,funname,...)
				return spytbl(varname)
			end
		end
		return original(...)
	end
	closures[f]=true
	return f
end
local spymt={
	__index=function(_,key)
		local varname=getnewvar((_[__25mslocation]:sub(1,1)~='_' and _[__25mslocation] or '')..(type(key)=='string' and key or ''))
		simplelog(varname,_[__25mslocation]..'['..tostring_complex(key)..']',Enum_NOCALL)
		if type(key)=='string' and _25mspredefined[key]==nil then
			return _25mspredefined[key]
		elseif key=='1il skid tried to dump' then
			return 1
		end
		if key=='IsStudio' then
			return function()return false end
		end
		return spytbl(varname)
	end,
	__newindex=function(_,key,value)
		insert(currentR,_[__25mslocation]..'['..tostring_complex(key)..']'..'='..tostring_complex(value)..(settings.log_lines and " -- line "..(function()
			local linenumber=debug.traceback():split'\n'
			for i,v in linenumber do
				if v:find('sandbox',1,true) then
					linenumber=v:split('*')[2]
					break
				end
			end
			return linenumber
		end)() or ''))
	end,
	__call=function(_,...)
		if type((...))=='string' and (...):find('This is a signature - If you are seeing this, you know what not to do :3',1,true) then
			insert(currentR,'_lol("<25ms: luarmor early exit>")')
			plserror=true
		end
		local varname=getnewvar('call'..(_[__25mslocation]:sub(1,1)~='_' and _[__25mslocation] or ''))
		simplelog(varname,_[__25mslocation],...)
		local spy=spytbl(varname)
		return spy
	end,
	__concat=function(left,right)
		local varname=getnewvar()
		simplelog(varname,tostring_complex(left)..' ... '..tostring_complex(right),Enum_NOCALL)
		return spytbl(varname)
	end,
	__tostring=function(_)
		return concat_me.._[__25mslocation]..concat_me_close
	end,
	__iter=function(_,funcused)
		local ran=false
		return function(t,...)
			if not ran then
				unclosed_blocks+=1
				local vars,varstr=genvars(2)
				local mid=_[__25mslocation]
				if funcused=='next' then
					mid='next,'..mid
				elseif funcused then
					mid='['..funcused..']({'..mid..'})'
				end
				insert(currentR,'for '..varstr..' in '..mid..' do')
				ran=true
				return unpack(vars)
			end
			unclosed_blocks-=1
			insert(currentR,'end')
		end
	end,
	__len=function(_)
		local returnvalue=math.random(1e3,1e9)
		local varname=getnewvar('len'..(_[__25mslocation]:sub(1,1)~='_' and _[__25mslocation] or ''))
		special_replacements[returnvalue]=varname
		insert(currentR,'local '..varname..' =#'.._[__25mslocation])
		return returnvalue
	end,
	__add=simplemath('+'),
	__sub=simplemath('-'),
	__mul=simplemath('*'),
	__div=simplemath('/'),
	__mod=simplemath('%'),
	__pow=simplemath('^'),
	__lt=simplemath('<'),
	__le=simplemath('<='),
	__eq=simplemath('=='),
	__unm=function(self)
		local varname=getnewvar()
		insert(currentR,'local '..varname..' ='..'-'..tostring_complex(self))
		return spytbl(varname)
	end,
	__type='context_type',
}
analyzefunction = function(chunk,r,lowestlayer,...)
	if plserror then return r end
	local oldR=currentR
	currentR=r
	local cenv=cenv['25msWasHere'] and {} or cenv
	cenv['25msWasHere']=true
	spytbl=function(pre,var_type)
		local tbl=setmetatable({
			[__25mslocation]=pre,
		},spymt)
		if var_type then
			types[tbl]=var_type
		end
		return tbl
	end
	if settings.hook_op==false then
		local log_if_needed=function(operation,a,b,actual)
			if type(a)=="context_type" or type(b)=="context_type" then
				local varname=getnewvar()
				local place_front=operation=='#' or operation=='not'
				simplelog(varname,(place_front and operation.." " or "")..tostring_complex(a)..(not place_front and " "..operation.." "..tostring_complex(b) or ""),Enum_NOCALL)
				local setting=settings.hook_op_default_return
				if setting=='spy' then
					return spytbl(varname)
				elseif setting=='original' then
					local success,result=pcall(actual)
					return success and result or 1
				else
					if operation=='not' then
						return not setting
					end
					return setting
				end
			end
			return actual()
		end
		cenv._25msLE=function(a,b) return log_if_needed('<',a,b,function()return(a < b)end) end
		cenv._25msGR=function(a,b) return log_if_needed('>',a,b,function()return(a > b)end) end
		cenv._25msLEQ=function(a,b) return log_if_needed('<=',a,b,function()return(a <= b)end) end
		cenv._25msGREQ=function(a,b) return log_if_needed('>=',a,b,function()return(a >= b)end) end
		cenv._25msNEQ=function(a,b) return log_if_needed('~=',a,b,function()return(a ~= b)end) end
		cenv._25msEQ=function(a,b) return log_if_needed('==',a,b,function()return(a == b)end) end
		cenv._25msNOT=function(a) return log_if_needed('not',a,nil,function()return(not a)end) end
		cenv._25msLEN=function(a) return log_if_needed('#',a,nil,function()return(#a)end) end
		cenv._25msAND=function(a,b)
			if type(a)=="context_type" then
				b=b()
				local varname=getnewvar()
				simplelog(varname,(tostring_complex(a)..' and '..tostring_complex(b)),Enum_NOCALL)
				if settings.hook_op_default_return=='original' then
					return a and b
				else
					return spytbl(varname)
				end
			elseif a then
				b=b()
				if type(b)=="context_type" then
					local varname=getnewvar()
					simplelog(varname,(tostring_complex(a)..' and '..tostring_complex(b)),Enum_NOCALL)
					return settings.hook_op_default_return=='spy' and spytbl(varname) or settings.hook_op_default_return=='original' and b
				end
				return a and b
			else
				return a and b()
			end
		end
		cenv._25msOR=function(a,b)
			local is_a_context=type(a)=="context_type"
			if is_a_context or not a then
				b=b()
				if is_a_context or type(b)=="context_type" then
					local varname=getnewvar()
					simplelog(varname,'('..tostring_complex(a)..' or '..tostring_complex(b)..')',Enum_NOCALL)
					return spytbl(varname)
				end
				return b
			else
				return a or b()
			end
		end
		cenv._25msIF=function(a)if type(a)=="context_type" then insert(currentR,'CHECKIF('..tostring_complex(a)..')')end return a end
		cenv._25msELSEIF=function(a)if type(a)=="context_type" then insert(currentR,'CHECKELSEIF('..tostring_complex(a)..')')end return a end
		local while_metas={}
		cenv._25msWHILE=function(a)
			if type(a)=="context_type" then
				if while_metas[a] then return false end
				insert(currentR,'CHECKWHILE('..tostring_complex(a)..')')
				while_metas[a]=true
			end
			return a
		end
		cenv._25msREPEAT=function(a)if type(a)=="context_type" then insert(currentR,'CHECKUNTIL('..tostring_complex(a)..')')end return a end
		cenv._25msINDEX=function(tbl)
			return setmetatable({},{
				__index=function(_,key)
					if type(tbl)=="context_type" and type(key)=="context_type" then
						local varname=getnewvar('idx')
						metatables[tbl]=metatables[tbl] or {
							mt=false,
							used=false
						}
						simplelog(varname,'('..tostring_complex(tbl)..')['..tostring_complex(key)..']',Enum_NOCALL)
						return spytbl(varname)
					end
					return tbl[key]
				end,
				__newindex=function(_,key,value)
					if type(tbl)=="context_type" and (type(key)=="context_type" and type(value)=="context_type") then
						metatables[tbl]=metatables[tbl] or {
							mt=false,
							used=false
						}
					end
					insert(currentR,'('..tostring_complex(tbl)..')['..tostring_complex(key)..'] = '..tostring_complex(value))
					tbl[key]=value
				end,
			})
		end
		cenv.setmetatable=function(tbl,mt)
			if type(tbl)=="context_type" or tbl==fenv_mt or type(mt)=="context_type" then
				local varname=getnewvar('setmetatable')
				simplelog(varname,'setmetatable',tbl,mt)
				return spytbl(varname)
			end
			metatables[tbl]={
				mt=mt,
				used=false
			}
			return setmetatable(tbl,mt)
		end
		cenv.setfenv=env.setfenv
		local game_meta=table.clone(spymt)
		game_meta.__call=function()
			return error('game cant be called')
		end
		if specialhandle=='moonveil' then
			local og_index=game_meta.__index
			game_meta.__index=function(_,key)
				if type(key)=="string" then
					if key:sub(1,1):lower()==key:sub(1,1) or key:sub(#key,#key):upper()==key:sub(#key,#key)then
						print('dtc',key)
						game_meta.__index=og_index
						error'moonveil is bad'
					end
				end
				return og_index(_,key)
			end
		end
		cenv.game=setmetatable({
			[__25mslocation]="game",
		},game_meta)
		cenv.Game=cenv.game
		for _,name in {
			"Instance","Drawing","UDim","CFrame","Color3","Vector3","UDim2","Vector2",
			"workspace","ypcall","gethwid","setfpscap","rconsoleprint",
			"rconsolewarn","package","makefolder","writefile","readfile","listfiles",
			"mkdir","isfile","delay","clonefunction","hookmetamethod",
			"setreadonly", "getrawmetatable", "fireproximityprompt",
			"ColorSequence","ColorSequenceKeypoint","Font","Workspace","cloneref",
			"TweenInfo","OverlapParams","setclipboard","toclipboard",
			"hookmetatable","hookfunction","base64","Random","RaycastParams","Ray",
			"restorefunction","script","hookfunction","print",
			"request","http_request","httpRequest","HttpRequest","http",
			"warn","getconnections","hash","NumberRange","NumberSequence",
			"Rect","NumberSequenceKeypoint","getgc",
			"getcustomasset","_VERSION","PhysicalProperties","queue_on_teleport",
			"shared","gethui","fireproximityprompt","crypt","getnamecallmethod",
			"getconstants","BrickColor","cleardrawcache","WebSocket","isrenderobj",
			"setrenderproperty","getrenderproperty","setidentity","setthreadcontext",
			"getidentity","getthreadcontext","getthreadidentity","setthreadidentity",
			"getsenv","getscripts","getscripthash","getrunningscripts","queueonteleport",
			"isrbxactive","isgameactive","cache","checkcaller","getupvalue","DeepCopy",
			"DateTime","input","time","Vector3int16","Vector2int16",
		} do
			cenv[name]=spytbl(name)
		end
		cenv.tick=function()return os.clock()end
		cenv.Random={
			new=function(seed)
				return {
					NextNumber=function(_,...)
						return math.random(...)
					end
				}
			end
		}
		cenv._VERSION="Luau"
		cenv.bit=bit32
		local spynewcclosure=spytbl("newcclosure")
		cenv.newcclosure=function(...)
			local func=...
			simplelog("_","newcclosure",...)
			local new_f=function(...)
				return func(...)
			end
			closures[new_f]=true
			return new_f
		end
		cenv.newlclosure=function(...)
			local func=...
			simplelog("_","newlclosure",...)
			return function(...)return func(...)end
		end
		closures[cenv.newcclosure]=true
		cenv.iscclosure=function(f)
			return not not closures[f]
		end
		cenv.islclosure=function(f)
			return not closures[f]
		end
		cenv.isexecutorclosure=function(...)
			simplelog("_","isexecutorclosure",...)
			return true
		end
		cenv.require=function(...)
			local varname=getnewvar('reg')
			simplelog(varname,'require',...)
			local t=type(...)
			if t=='string' and string.sub(...),1,1)=='@' then
				if (...)=='@self' or (...)=='@game' then
					error'Unable to require module from given path'
				elseif string.sub(...),1,6)=='@game/' then
					error(''..string.sub(...),7)..' is not a valid Service name')
				end
				error'Path contains unsupported'
			elseif t=='context_type' or t=='number' or t=='userdata' then
				error('expected a ModuleScript, got '..type(...))
			end
			return spytbl(varname)
		end
		for _,name in pairs({'table','string','math','debug','os','coroutine','buffer'}) do
			local og=env[name]
			cenv[name]={}
			for i,func in pairs(og) do
				if i=='insert' then
					cenv[name][i]=og[i]
					continue
				elseif type(func)=='function' then
					cenv[name][i]=func
				else
					cenv[name][i]=function(...)
						local a,b,c=...
						local has_context=false
						for _,v in {...} do
							if type(v)=="context_type" then
								has_context=true
								break
							end
						end
						if name=='debug' and (i=='info' or i=='getinfo') then
							print('debug.info called with',a,b,c)
							local isnumber=type(a)=='number'
							if isnumber and a<0 then
								return error('invalid argument #1 to \'info\' (level can\'t be negative)')
							elseif a==0 and b=='l' then
								return -1
							elseif isnumber and a>1 then
								for i=1,a+2 do
									local targetfunc=debug.info(i,'f')
									if targetfunc==analyzefunction then
										return
									end
								end
							end
							a=isnumber and a+1 or a
							print(a)
							local res=pack(func(a,b,c))
							if b=='slnaf' then
								local diddename
								for i,v in pairs(cenv) do
									if (...) == v then
										diddename=i
									end
								end
								print('didded',diddename)
								return '[C]',-1,diddename or '',0,true,a
							end
							return smart_unpack(res)
						elseif i=='char' and name=='string' and a==nil then
							return ''
						elseif i=='concat' and name=='table' then
							for i,v in pairs(...) do
								if type(v)=="context_type" then
									(...) [i]=concat_me..tostring_complex(v)..concat_me_close
								end
							end
						elseif i=='create' and name=='table' then
							if a<0 then return {} end
						end
						if i=="find" and type(a)=="function" then
							local varname=getnewvar("find")
							simplelog(varname,"string.find",a,b,c)
							return spytbl(varname)
						end
						local real_res=has_context and not table.find({"pack","move","unpack"},i) or {func(...)}
						if i=="traceback" and name=="debug" and type(real_res[1])=="string" then
							print(real_res[1])
							real_res[1]=real_res[1]:gsub("%[string \"%.\\httplog2\"%]:%d+\n",""):gsub("%[string \"sandbox\"%]:(%d+)\n","[string \"sandbox\"]:%1\n")
						end
						if (has_context and not table.find({"pack","move","unpack"},i) or real_res[1]=="[string \"./httplog2\"]") then
							local vars,varstr=genvars(3)
							simplelog(varstr,name.."."..i,...)
							return unpack(vars)
						end
						return unpack(real_res)
					end
				end
				closures[cenv[name][i]]=true
			end
			if name=="debug" then
				cenv.debug.getinfo=debug_getinfo
				for i,v in pairs({"getupvalue","getlocal","setlocal","sethook","getregistry","getmetatable","setmetatable","setupvalue"}) do
					cenv.debug[v]=spytbl("debug."..v,"function")
				end
			end
			if name~="debug" then table.freeze(cenv[name]) end
		end
		cenv.Enum=spytbl("Enum")
		cenv.pcall=function(...)
			if plserror then plserror=nil;error("<25ms: forcederror>") end
			local res={_pcall(...)}
			if res[1] == false then
				res[2] = tostring(res[2])
			end
			return unpack(res)
		end
		if input:find("newproxy, setmetatable, getmetatable, select,",1,true) then
			local error_just_called
			cenv.pcall = function(...)
				local results = {_pcall(...)}
				if error_just_called then
					error_just_called = false
					return unpack(results)
				end
				local first = results[1]
				if type(first) == "boolean" and first == false then
					local second = results[2]
					if type(second) == "string" then
						results[2] = (second:gsub(":(%d+)([:\r\n])", ":1%2"))
					end
				end
				return unpack(results)
			end
			local _error = error
			cenv.error = function(...)
				error_just_called = true
				return _error(...)
			end
		end
		for _,v in pairs({"pairs","ipairs"}) do
			cenv[v]=function(tbl)
				if not tbl then
					insert(currentR,"for i,v in "..v.."(nil)do end")
					return
				end
				if type(tbl)=="context_type" then
					local mt=getmetatable(tbl)
					if not mt or not mt.__iter then
						simplelog("_",v,tbl)
						return function()end
					end
					return mt.__iter(tbl,v)
				else return env[v](tbl)
				end
			end
		end
		local nextcalls={}
		cenv.next=function(tbl,...)
			if type(tbl)=="context_type" then
				if ... and nextcalls[tbl] then
					return nextcalls[tbl](tbl,...)
				end
				local func=getmetatable(tbl).__iter(tbl,"next")
				nextcalls[tbl]=func
				return func(tbl,...)
			else return env.next(tbl,...)
			end
		end
		cenv.ishooked=function(...)
			simplelog("_","ishooked",...)
			return false
		end
		cenv.IsHooked=function(...)
			simplelog("_","IsHooked",...)
			return false
		end
		cenv.isfunctionhooked=function(...)
			simplelog("_","isfunctionhooked",...)
			return false
		end
		cenv.wait=function(...)simplelog("_","wait",...);return ((...) or 0)+math.random()/10 end
		cenv.loadstring=function(src,...)
			local varname=getnewvar()
			if type(src)=="string" then
				if not(type(src)=="string" and src:find(".@%(/*,....... ...,,*/(#%&@@.\n (* ,/(#%%&&@@@@&",1,true)) then
					simplelog(varname,"loadstring",src,...)
				end
				src=settings.hook_op and hook_op(src) or src
				local success,_func,a=_pcall(luau.load,src,(...) or "25ms_loadstring")
				if not success then
					return nil,_func
				end
				local _funcenv=getfenv(_func)
				if _funcenv.require~=cenv.require then
					setfenv(_func,setmetatable({},{__index=function(_,key)
						return cenv[key] or _funcenv[key]
					end}))
				end
				return _func,a
			elseif type(src)=="context_type" then
				simplelog(varname,"loadstring",src)
				return function(...)
					local func_varname=getnewvar()
					simplelog(func_varname,varname,...)
					return spytbl(func_varname)
				end
			end
		end
		if msecNotReady then
			cenv.allowLogging=function()
				msecNotReady=false
				cenv.allowLogging=nil
				cenv.SetCenv=nil
			end
			cenv.SetCenv=function(key,value)
				cenv[key]=value
			end
		end
		cenv.ce_like_loadstring_fn=cenv.loadstring
		cenv.script_key="c4ce76cd36f2afee4dcee7e87576e5fa"
		local _rawset=rawset
		local tsenv={}
		cenv.getgenv=function()
			return setmetatable({
				[__25mslocation]="genv",
			},{
				__index=function(_,key)
					local varname=getnewvar()
					insert(currentR,"local "..varname.."=genv["..stringify(key).."]")
					if settings.spynilglobals and _25mspredefined[key]==nil and genv[key]==nil then
						return spytbl(varname)
					end
					return _25mspredefined[key] or genv[key] or cenv[key]
				end,
				__newindex=function(_,k,v)
					genvused=true
					insert(currentR,"genv["..stringify(k).."]="..tostring_complex(v))
					genv[k]=v
				end,
				__type="context_type"
			})
		end
		cenv.getenv=function()
			return setmetatable({
				[__25mslocation]="renv",
			},{
				__index=cenv,
				__newindex=function(_,k,v)
					insert(currentR,"getenv()["..stringify(k).."]="..tostring_complex(v))
				end,
				__type="context_type"
			})
		end
		cenv._G=setmetatable({
			[__25mslocation]="_G"
		},{
			__index=function(_,key)
				insert(currentR,"local _=_G["..stringify(key).."]")
				print(key)
				return rawget(_,key) or _25mspredefined[key] or cenv[key] or genv[key]
			end,
			__newindex=function(_,k,v)
				insert(currentR,"_G["..stringify(k).."]="..tostring_complex(v)..(settings.log_lines and " -- line "..(function()
					local linenumber=debug.traceback():split"\n"
					for i,v in linenumber do
						if v:find("sandbox",1,true) then
							linenumber=v:split(":")[2]
							break
						end
					end
					return linenumber
				end)() or ""))
				rawset(_,k,v)
			end,
			__type='context_type'
		})
		cenv.task=setmetatable({
			wait=function(...)simplelog("_","task.wait",...);return ((...or 0)+math.random()/10) end,
			[__25mslocation]='task'
		},{
			__index=spytbl('task'),
			__type='context_type',
		})
		cenv.spawn=function(f,...)f(...)end
		cenv.getenv=function(lvl)
			local originvl=lvl
			if type(lvl)=='number' and lvl<0 then return error('invalid argument #1 to \'getenv\' (level must be non-negative)') end
			if type(lvl)=='boolean' then return error('invalid argument #1 to \'getenv\' (number expected, got boolean)') end
			lvl=lvl and (type(lvl)=='number' and lvl+1 or lvl) or 2
			local res=getfenv((table.find({'function','number'},type(lvl)) and lvl or nil))
			local res_mt=getmetatable(res)
			if rawget(res,'require')==require or (type(res_mt)=='table' and type(res_mt.__index)=='table' and res_mt.__index.require==require) then
				return fenv_mt
			end
			return res
		end
		cenv.identifyexecutor=function()
			local vars,varstr=genvars(2)
			simplelog(varstr,'identifyexecutor')
			return vars[1],vars[2]
		end
		cenv.getexecutorname=function()
			local varname=getnewvar()
			simplelog(varname,'getexecutorname')
			return spytbl(varname)
		end
		local fake_file_system={}
		cenv.writefile=function(path,cont)
			simplelog("_",'writefile',path,cont)
			fake_file_system[path]=cont
		end
		cenv.appendfile=function(path,cont)
			simplelog("_",'appendfile',path,cont)
			if fake_file_system[path] then
				fake_file_system[path]=fake_file_system[path]..cont
			else
				fake_file_system[path]=cont
			end
		end
		cenv.readfile=function(path)
			local varname=getnewvar()
			return fake_file_system[path]
		end
		cenv.isfile=function(path)
			return fake_file_system[path]~=nil
		end
		cenv.isfolder=function(path)
			return fake_file_system[path]~=nil
		end
		cenv.mkdir=function(path)
			simplelog("_",'mkdir',path)
			fake_file_system[path]={}
		end
		cenv.listfiles=function(path)
			local varname=getnewvar()
			simplelog(varname,'listfiles',path)
			local res={}
			for i,v in pairs(fake_file_system) do
				if table.concat(v:reverse():split("/"),"/",2):reverse()==path then
					insert(res,i)
				end
			end
			return spytbl(varname)
		end
		for i,v in pairs(cenv) do
			genv[i] = v
		end
		local typin_check=false
		cenv._25missingfunction=function(...) if ...=='meow:3' then error('Controlled shutdown') end end
		cenv.type=function(...)
			local res=type(...)
			if ...=='25ms is such a god' then typin_check=true;return "my dhh hurts"
			elseif typin_check==true and res=='table' and (...)[1]=='bat is gay' then
				local calledtimes,extreme_mow=math.random(1,10),0
				local meow_obj
				for i=1,calledtimes do
					local len=math.random(1,3)
					local str=string.rep('x',len)
					if extreme_mow+len>100 then
						str=""
					else
						extreme_mow+=len
					end
					meow_obj=(...)[str]
				end
				meow_obj[__25mslocation]=meow_obj
				setmetatable(meow_obj,{
					__index=function(_,key)
						if key==extreme_mow then
							return string.rep('x',calledtimes-1)..'\x1B'
						elseif key==420 then
							return '\x1B'
						end
						return string.rep('x',math.random(1,20))
					end,
					__type="context_type",
					__metatable=false
				})
				return nil
			end
			if closures(...) then
				return "function"
			elseif types(...) then
				return types(...)
			elseif res=="context_type" then
				simplelog('_','type',...)
				return 'table'
			end
			return res
		end
		cenv.typeof=cenv.type
		local oldgetmt=getmetatable
		cenv.getmetatable=function(t)
			if type(t)=="context_type" or t==fenv_mt then
				local varname=getnewvar()
				simplelog(varname,'getmetatable',t)
				return spytbl(varname)
			end
			return oldgetmt(t)
		end
		cenv.rawget=function(t,k)
			if (type(t)=="context_type" or type(k)=="context_type") and not type(k)=="table" then
				local varname=getnewvar('rawget')
				simplelog(varname,'rawget',t,k)
				return spytbl(varname)
			end
			return rawget(t,k)
		end
		for _,func in pairs({"newproxy","unpack","rawset"}) do
			cenv[func]=function(...)
				simplelog("_",func,...)
				local varname=getnewvar()
				return spytbl(varname)
			end
		end
		cenv.ipairs=cenv.ipairs
		cenv.pairs=cenv.pairs
		cenv.select=function(...)
			simplelog("_",'select',...)
			local varname=getnewvar()
			return spytbl(varname)
		end
		cenv.require=cenv.require
		local function b_loadstring(f,source)
			local varname=getnewvar()
			simplelog(varname,'loadstring',source)
			return spytbl(varname)
		end
		cenv.loadstring=b_loadstring
		cenv.load=b_loadstring
		local blocked_upvalues={}
		local mt_25ms_globals=setmetatable({},{__index=cenv,__newindex=cenv,__type="context_type"})
		local fenv_mt
		fenv_mt=setmetatable({
			[__25mslocation]="fenv"
		},{
			__index=function(_,key)
				local lastlen=#currentR
				if key==nil then
					print(key)
					return
				end
				if not predefinedfound and key=='_25mspredefine' and input:find('_25mspredefine',1,true) then
					predefinedfound=true
					simplelog('_','_25mspredefine','this function was referenced in the script, if you didn\'t do this place _25mspredefine(true) somewhere above your dump')
					return function(t)
						for i,v in t do
							_25mspredefined[i]=v
						end
					end
				end
				if luraphnotready==1 and key=='coroutine' then
					luraphnotready=2
				elseif luraphnotready==2 and key=='bit32' then
					luraphnotready=3
					print"reached 3"
				elseif luraphnotready==3 and key=='select' then
					luraphnotready=4
				elseif luraphnotready==4 and key=='table' then
					luraphnotready=5
					print"reached 5"
				elseif luraphnotready==5 then
					if key=='loadstring' then
						return function(src,...)
							luraphnotready=0
							print("done!!!!!!!!!!!!!!!!")
							return luau.load(src,...)
						end
					elseif key=='require' then
						return function()return {}end
					end
				end
				if #currentR==lastlen then
					fuck+=1
					if fuck>fenv_error_on+2 then
						plserror=true
					elseif fuck>fenv_error_on then
						error("<25ms: infiniteleopofenv>")
					end
				else
					fuck=0
				end
				lastlen=#currentR
				local try=_25mspredefined[key] or tsenv[key] or cenv[key]
				if try~=nil then
					return try
				elseif key=="IsChooseTeam" then
					return function()return true end
				elseif (env[key]==nil) then
					if not logged_undefined_fenv[key] and not (type(key)=="string" and #key>=12 and #key<=14 and settings.ignore_prom_globals) then
						fenvused=true
						local varname=getnewvar(key)
						logged_undefined_fenv[key]=varname
						insert(currentR,"local "..varname.."=fenv["..tostring_complex(key).."]")
					end
					if settings.spynilglobals and not (#key>=12 and #key<=14 and settings.ignore_prom_globals) then return spytbl(logged_undefined_fenv[key]) end
					return env[key] or genv[key]
				end
			end,
			__newindex=function(_,k,v)
				if k=="_" or #k>50 then return end
				fenvused=true
				if not table.find({"Db","Dc"},k) and not msecNotReady then
					if k=="MoonSec_StringsHiddenAttr" then
						settings.spynilglobals=settings.spynilglobals==nil or settings.spynilglobals
						settings.hook_op=settings.hook_op==nil or settings.hook_op
						settings.usesimplefunctions=settings.usesimplefunctions==true
					end
					if k=="Descriptor" or type(k)=="string" and k:sub(1,10)=="FlatIdent_" then
					else
						insert(currentR,`fenv[{tostring_complex(k)}] = {tostring_complex(v)}`..(settings.log_lines and " -- line "..(function()
							local linenumber=debug.traceback():split"\n"
							for i,v in linenumber do
								if v:find("sandbox",1,true) then
									linenumber=v:split(":")[2]
									break
								end
							end
							return linenumber
						end)() or ""))
					end
				end
				tsenv[k]=v
			end,
			__metatable=false,
		})
		setfenv(chunk,fenv_mt)
	end
	local p
	if lowestlayer and luraphcarry then
		chunk=function()error"v14.6 support soon sorry gays"end
		p=table.pack(_pcall(chunk,luraphcarry))
	else p = table.pack(_pcall(chunk,unpackchoose(varargs,...))) end
	if not p[1] and type(p[2])=="string" then
		p[2]=p[2]:gsub("%[string \"sandbox\"%]:","line "):gsub("%[string \"%.[\\/]httplog2\"%]:","internal ")
		simplelog("er","error",unpack(p,2))
	elseif not p[1] then
		simplelog("er","error")
	else
		local function get(num)
			if not num or num==0 then return end
			if num>100 then
				return nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,nil
			elseif num>10 then
				return nil,nil,nil,nil,nil,nil,nil,nil,nil,nil,get(num-10)
			end
			return nil, get(num-1)
		end
		if p.n>1 then
			insert(r,"return "..stringify(unpack(p,2,p.n)))
		end
	end
	currentR=oldR
	return r
end
local r={
}
local start=clock()
local s,re=pcall(analyzefunction,chunk,r,true)
if not s then print("heh",s,re) end
local post=commercial and "_dump.lua" or ".lua"
for i=1,unclosed_blocks do
	insert(r,"end")
end
if fenvused then
	insert(r,1,"local fenv=getfenv()")
end
if genvused then
	insert(r,1,"local genv=getgenv()")
end
for i=1,20 do
	if not is_unfinished then break end
	local newr={}
	for _,line in pairs(r) do
		local num=line:match("-- func(%d+)")
		if num and unfinishedfuncs[tonumber(num)] then
			local locallocation,localused=#newr,false
			local localname=newr[locallocation]:match("local ([%w_]+)")
			local obj=unfinishedfuncs[tonumber(num)]
			local s,re=pcall(analyzefunction,obj.func,{},false,multiunpack(obj.args,obj.varargs))
			for i,v in pairs(re) do
				if v~=nil then
					if v:find(localname,1,true) then
						localused=true
					end
					insert(newr,v)
				end
			end
			if localused then
				newr[locallocation]=newr[locallocation]:gsub("(local )([%w_]+)","%2")
				insert(newr,locallocation,"local "..localname)
			end
		else
			insert(newr,line)
		end
	end
	r=newr
end
if not settings.log_lines then
	local total_before=#r
	local start=os.clock()
	r=evaluate_single_use_variables(r)
	evaluate_stuff(r)
	print("evaluating in ",os.clock()-start,"seconds")
	print("reduced from",total_before,"to",#r,"lines")
else
	local oldr=table.clone(r)
	table.clear(r)
	for _,v in oldr do
		if v~=nil then
			insert(r,(v:gsub(identifier.."_?","")))
		end
	end
end
fs.writeFile(outpath..targetfilename:gsub(".lua","")..post,table.concat(r,"\n"))
local endt=clock()-startt
print("success in",endt,"seconds!\nWritten to "..outpath..targetfilename:gsub(".lua","")..post)
print(table.concat(r,"\n"))
