const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateFlamecoder(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_deobf.lua`);
    
    return new Promise((resolve, reject) => {
        const luaProcess = spawn('lua', [
            path.join(__dirname, '../scripts/flamecoder_deobf.lua'),
            inputFile,
            outputFile
        ]);
        
        let stderr = '';
        luaProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
        luaProcess.on('close', (code) => {
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                cleanup(inputFile, outputFile);
                resolve(result);
            } else {
                const extracted = extractDeobfuscated(stderr);
                cleanup(inputFile, outputFile);
                if (extracted) resolve(extracted);
                else reject(new Error('Flamecoder deobfuscation failed'));
            }
        });
    });
}

function extractDeobfuscated(stderr) {
    const match = stderr.match(/\[HOOKOP\] (.*)/);
    if (match) return match[1];
    
    const lines = stderr.split('\n');
    for (const line of lines) {
        if (line.includes('local fenv = getfenv()') || line.includes('local env = _G')) {
            let extracted = '';
            let startIdx = lines.indexOf(line);
            for (let i = startIdx; i < Math.min(startIdx + 200, lines.length); i++) {
                extracted += lines[i] + '\n';
                if (lines[i].includes('return ') && i > startIdx + 10) break;
            }
            return extracted;
        }
    }
    return null;
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateFlamecoder };
