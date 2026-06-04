const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateMoonsec(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    
    fs.writeFileSync(inputFile, code, 'utf8');
    
    return new Promise((resolve, reject) => {
        const luaProcess = spawn('lua', [
            path.join(__dirname, '../scripts/moonsec_deobf.lua'),
            inputFile,
            outputFile
        ]);
        
        let stderr = '';
        luaProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
        luaProcess.on('close', (code) => {
            cleanup(inputFile, outputFile);
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                resolve(result);
            } else {
                const fallback = performBasicDeobfuscation(code);
                resolve(fallback);
            }
        });
        
        luaProcess.on('error', (err) => {
            cleanup(inputFile, outputFile);
            resolve(performBasicDeobfuscation(code));
        });
    });
}

function performBasicDeobfuscation(code) {
    let result = code;
    result = result.replace(/local\s+_ENV\s*=\s*setmetatable\([^,]+,\s*{[^}]+}\)/g, '');
    result = result.replace(/getfenv\(\)\._ENV\s*=\s*getfenv\(\)/g, '');
    result = result.replace(/_ENV\[(["'])([^"']+)\1\]/g, '$2');
    result = result.replace(/_ENV\.([a-zA-Z_][a-zA-Z0-9_]*)/g, '$1');
    return result;
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateMoonsec };
