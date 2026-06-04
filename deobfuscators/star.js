const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateStar(code) {
    let result = code;
    
    result = result.replace(/STAR OBFUSCATOR[^\n]*\n/, '');
    result = result.replace(/--\[\[ STAR[^\]]*\]\]/g, '');
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\[\[([^\]]*)\]\]/g;
    let match;
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const arrayName = match[1];
        const content = match[2];
        const strings = content.split('|');
        
        const accessPattern = new RegExp(`${arrayName}:sub\\((\\d+),\\s*(\\d+)\\)`, 'g');
        result = result.replace(accessPattern, (_, start, end) => {
            const s = parseInt(start);
            const e = parseInt(end);
            if (s > 0 && e <= strings.length) {
                return JSON.stringify(strings[s - 1].substring(0, e - s + 1));
            }
            return `"${strings[s - 1] || ''}"`;
        });
    }
    
    result = result.replace(/local\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*local\s+[a-z]\s*=\s*\{[^}]+\}\s*return\s+function\([^)]*\)/g, 'function(');
    
    result = await beautifyLua(result);
    
    return result;
}

async function beautifyLua(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_beautified.lua`);
    
    fs.writeFileSync(inputFile, code, 'utf8');
    
    return new Promise((resolve) => {
        const { spawn } = require('child_process');
        const luamin = spawn('npx', ['luamin', '-f', inputFile, '-o', outputFile]);
        
        luamin.on('close', () => {
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                cleanup(inputFile, outputFile);
                resolve(result);
            } else {
                cleanup(inputFile, outputFile);
                resolve(code);
            }
        });
    });
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateStar };
