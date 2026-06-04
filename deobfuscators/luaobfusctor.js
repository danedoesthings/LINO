const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateLuaObfuscator(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    let processedCode = code;
    
    processedCode = processedCode.replace(/local\s+_0x[a-f0-9]+\s*=\s*\{[^}]+\}/g, '');
    processedCode = processedCode.replace(/local\s+function\s+_0x[a-f0-9]+\([^)]*\)[^{]*\{/g, 'function(');
    
    const stringDecryptPattern = /_0x([a-f0-9]+)\(["']([^"']+)["']\)/g;
    processedCode = processedCode.replace(stringDecryptPattern, (_, id, str) => {
        if (id.length === 4) return `"${str}"`;
        return `"${str}"`;
    });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, processedCode, 'utf8');
    
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_beautified.lua`);
    
    return new Promise((resolve, reject) => {
        const luamin = spawn('npx', [
            'luamin',
            '-f', inputFile,
            '-o', outputFile
        ]);
        
        luamin.on('close', (code) => {
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                cleanup(inputFile, outputFile);
                resolve(result);
            } else {
                cleanup(inputFile, outputFile);
                resolve(processedCode);
            }
        });
        
        luamin.on('error', () => {
            cleanup(inputFile, outputFile);
            resolve(processedCode);
        });
    });
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateLuaObfuscator };
