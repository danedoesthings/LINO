const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscate25ms(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_deobf.lua`);
    
    return new Promise((resolve, reject) => {
        const luaProcess = spawn('lune', [
            'run',
            path.join(__dirname, '../scripts/twenty5ms_deobf.lua'),
            inputFile,
            outputFile
        ]);
        
        let stdout = '', stderr = '';
        luaProcess.stdout.on('data', (data) => { stdout += data.toString(); });
        luaProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
        luaProcess.on('close', (code) => {
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                cleanup(inputFile, outputFile);
                resolve(result);
            } else {
                const extracted = extractFromEnvLogger(stdout);
                cleanup(inputFile, outputFile);
                if (extracted) resolve(extracted);
                else reject(new Error(`25ms deobfuscation failed: ${stderr || stdout || 'Unknown error'}`));
            }
        });
    });
}

function extractFromEnvLogger(output) {
    const lines = output.split('\n');
    const codeLines = [];
    let capturing = false;
    
    for (const line of lines) {
        if (line.includes('--[[ Generated') || line.includes('-- Dumped')) {
            capturing = true;
        }
        if (capturing && !line.includes('pcall') && !line.includes('xpcall')) {
            codeLines.push(line);
        }
        if (capturing && line.includes('return ') && codeLines.length > 5) {
            capturing = false;
        }
    }
    
    if (codeLines.length > 0) return codeLines.join('\n');
    return null;
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscate25ms };
