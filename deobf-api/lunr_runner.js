const fs = require('fs');
const fengari = require('fengari');
const lua = fengari.lua;
const lauxlib = fengari.lauxlib;
const lualib = fengari.lualib;
const interop = require('fengari-interop');

const scriptPath = process.argv[2];
const outputPath = process.argv[3] || 'captured.lua';

const scriptContent = fs.readFileSync(scriptPath, 'utf8');

const L = lauxlib.luaL_newstate();
lualib.luaL_openlibs(L);
interop.luaopen_js(L);

const harnessCode = fs.readFileSync('./lunr_harness.lua', 'utf8');

if (lauxlib.luaL_dostring(L, fengari.to_luastring(harnessCode)) !== lua.LUA_OK) {
    const err = lua.lua_tostring(L, -1);
    console.error('Harness load error:', fengari.to_jsstring(err));
    process.exit(1);
}

lua.lua_getfield(L, -1, fengari.to_luastring('dump_string'));
lua.lua_pushstring(L, fengari.to_luastring(scriptContent));

if (lua.lua_pcall(L, 1, 2, 0) !== lua.LUA_OK) {
    const error = lua.lua_tostring(L, -1);
    const errorStr = fengari.to_jsstring(error);
    if (errorStr.includes("error('lunr:")) {
        const lines = errorStr.split('\n');
        const output = lines.slice(1).join('\n').trim();
        if (output) {
            fs.writeFileSync(outputPath, output);
            process.exit(0);
        }
    }
    console.error('Error:', errorStr);
    process.exit(1);
}

const success = lua.lua_toboolean(L, -2);
const result = lua.lua_tostring(L, -1);
const resultStr = fengari.to_jsstring(result);

if (success && resultStr) {
    fs.writeFileSync(outputPath, resultStr);
} else {
    fs.writeFileSync(outputPath, '-- No output');
}
lua.lua_close(L);
