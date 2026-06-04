const crypto = require('crypto');

async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/LuaObfuscator\.com[^\n]*\n/, '');
    result = result.replace(/local\s+_0x[a-f0-9]+\s*=\s*\{[^}]+\}/g, '');
    
    const stringDecryptPattern = /_0x([a-f0-9]+)\(["']([^"']+)["']\)/g;
    result = result.replace(stringDecryptPattern, (_, id, str) => {
        return `"${str}"`;
    });
    
    const varPattern = /_0x[a-f0-9]+/g;
    result = result.replace(varPattern, 'var');
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    result = result.replace(/local\s+_ENV\s*=\s*{[^}]+}/g, '');
    result = result.replace(/getfenv\(\)\._ENV\s*=\s*getfenv\(\)/g, '');
    
    return result;
}

module.exports = { deobfuscate };
