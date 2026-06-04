const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateHolyLua(code) {
    let result = code;
    
    result = result.replace(/--\[\[holylua[^\]]*\]\]/gi, '');
    result = result.replace(/holylua\s*=\s*{[^}]+}/gi, '');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{((?:[^,}]+,?)+)\}/g;
    let match;
    const stringArrays = [];
    
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                strings.push(JSON.parse(sm));
            }
            stringArrays.push({ name: match[1], strings });
        }
    }
    
    for (const arr of stringArrays) {
        const accessPattern = new RegExp(`${arr.name}\\[(\\d+)\\]`, 'g');
        result = result.replace(accessPattern, (_, idx) => {
            const index = parseInt(idx);
            if (index > 0 && index <= arr.strings.length) {
                return JSON.stringify(arr.strings[index - 1]);
            }
            return `"string_${idx}"`;
        });
    }
    
    const xorPattern = /bit32\.bxor\(([^,]+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, val, key) => {
        const num = parseInt(val);
        if (!isNaN(num)) return String(num ^ parseInt(key));
        return `bit32.bxor(${val}, ${key})`;
    });
    
    result = result.replace(/local\s+_ENV\s*=\s*{[^}]+}/g, '');
    result = result.replace(/getfenv\(\)\._ENV\s*=\s*getfenv\(\)/g, '');
    
    return result;
}

module.exports = { deobfuscate: deobfuscateHolyLua };
