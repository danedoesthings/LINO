const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateBoronide(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    let processedCode = code;
    
    processedCode = processedCode.replace(/Boronide\s*=\s*{[^}]+}/g, '');
    processedCode = processedCode.replace(/Hercules\s*=\s*{[^}]+}/g, '');
    
    const stringTablePattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    const stringMaps = [];
    let match;
    
    while ((match = stringTablePattern.exec(processedCode)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                strings.push(JSON.parse(sm));
            }
            stringMaps.push({ name: match[1], strings });
        }
    }
    
    for (const map of stringMaps) {
        const accessPattern = new RegExp(`${map.name}\\[(\\d+)\\]`, 'g');
        processedCode = processedCode.replace(accessPattern, (_, idx) => {
            const index = parseInt(idx) - 1;
            return JSON.stringify(map.strings[index] || 'unknown');
        });
    }
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_beautified.lua`);
    
    fs.writeFileSync(inputFile, processedCode, 'utf8');
    
    return new Promise((resolve) => {
        const luamin = spawn('npx', ['luamin', '-f', inputFile, '-o', outputFile]);
        
        luamin.on('close', () => {
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                cleanup(inputFile, outputFile);
                resolve(result);
            } else {
                cleanup(inputFile, outputFile);
                resolve(processedCode);
            }
        });
    });
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateBoronide };
