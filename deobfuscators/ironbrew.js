const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateIronbrew(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_deobf.lua`);
    
    return new Promise((resolve, reject) => {
        const deobfProcess = spawn('node', [
            path.join(__dirname, '../node_modules/.bin/luamin'),
            inputFile,
            '--beautify'
        ]);
        
        let beautified = '';
        deobfProcess.stdout.on('data', (data) => { beautified += data.toString(); });
        
        deobfProcess.on('close', (code) => {
            if (code !== 0) {
                cleanup(inputFile, outputFile);
                reject(new Error('Ironbrew beautification failed'));
                return;
            }
            
            const deobfuscated = performIronbrewDeobfuscation(beautified);
            fs.writeFileSync(outputFile, deobfuscated, 'utf8');
            const result = fs.readFileSync(outputFile, 'utf8');
            cleanup(inputFile, outputFile);
            resolve(result);
        });
    });
}

function performIronbrewDeobfuscation(code) {
    let result = code;
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{([^}]+)\}/g;
    const stringMap = new Map();
    let match;
    
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const arrayName = match[1];
        const contents = match[2];
        const strings = [];
        let strMatch;
        const strPattern = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
        while ((strMatch = strPattern.exec(contents)) !== null) {
            strings.push(strMatch[1]);
        }
        stringMap.set(arrayName, strings);
    }
    
    for (const [arrayName, strings] of stringMap) {
        const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
        result = result.replace(accessPattern, (_, index) => {
            const idx = parseInt(index) - 1;
            return strings[idx] ? JSON.stringify(strings[idx]) : `"string_${idx}"`;
        });
    }
    
    const xorPattern = /bit32\.bxor\(([^,]+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, value, key) => {
        try {
            const num = parseInt(value);
            if (!isNaN(num)) return String(num ^ parseInt(key));
            return `bit32.bxor(${value}, ${key})`;
        } catch (e) {
            return `bit32.bxor(${value}, ${key})`;
        }
    });
    
    result = result.replace(/local\s+_ENV\s*=\s*setmetatable\([^,]+,\s*{[^}]+}\)/g, '');
    result = result.replace(/getfenv\(\)\._ENV\s*=\s*getfenv\(\)/g, '');
    
    return result;
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateIronbrew };
