const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateLuaObfuscator(code) {
    let result = code;
    
    result = result.replace(/local\s+_0x[a-f0-9]+\s*=\s*\{[^}]+\}/g, '');
    result = result.replace(/local\s+function\s+_0x[a-f0-9]+\([^)]*\)[^{]*\{/g, 'function(');
    
    const stringDecryptPattern = /_0x([a-f0-9]+)\(["']([^"']+)["']\)/g;
    result = result.replace(stringDecryptPattern, (_, id, str) => `"${str}"`);
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    return result;
}

module.exports = { deobfuscate: deobfuscateLuaObfuscator };
