const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscate(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    let result = code;
    
    result = result.replace(/local\s+_ENV\s*=\s*setmetatable\([^,]+,\s*{[^}]+}\)/g, '');
    result = result.replace(/getfenv\(\)\._ENV\s*=\s*getfenv\(\)/g, '');
    result = result.replace(/local\s+_0x[a-f0-9]+\s*=\s*{[^}]+}/g, '');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let match;
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                strings.push(JSON.parse(sm));
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => {
                const index = parseInt(idx);
                return JSON.stringify(strings[index - 1] || 'unknown');
            });
        }
    }
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    fs.unlinkSync(inputFile);
    
    return result;
}

module.exports = { deobfuscate };
