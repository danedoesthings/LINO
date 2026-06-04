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
            if (code !== 0) {
                cleanup(inputFile, outputFile);
                reject(new Error(`Moonsec deobfuscation failed: ${stderr || 'Unknown error'}`));
                return;
            }
            
            if (!fs.existsSync(outputFile)) {
                cleanup(inputFile, outputFile);
                reject(new Error('No output file generated'));
                return;
            }
            
            const result = fs.readFileSync(outputFile, 'utf8');
            cleanup(inputFile, outputFile);
            resolve(result);
        });
        
        luaProcess.on('error', (err) => {
            cleanup(inputFile, outputFile);
            reject(err);
        });
    });
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateMoonsec };
