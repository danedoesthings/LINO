const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateLuraph(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    return new Promise((resolve, reject) => {
        const luaProcess = spawn('lua', [
            path.join(__dirname, '../scripts/luraph_deobf.lua'),
            inputFile
        ]);
        
        let stdout = '', stderr = '';
        luaProcess.stdout.on('data', (data) => { stdout += data.toString(); });
        luaProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
        luaProcess.on('close', (code) => {
            cleanup(inputFile);
            
            if (stdout.includes('Deobfuscated successfully') || stdout.includes('Done')) {
                const extracted = extractLuraphCode(stdout);
                if (extracted) resolve(extracted);
                else resolve(stdout);
            } else if (stderr) {
                const extracted = extractFromError(stderr);
                if (extracted) resolve(extracted);
                else reject(new Error(`Luraph deobfuscation failed: ${stderr}`));
            } else {
                reject(new Error('Luraph deobfuscation failed'));
            }
        });
    });
}

function extractLuraphCode(output) {
    const lines = output.split('\n');
    const codeLines = [];
    let capturing = false;
    
    for (const line of lines) {
        if (line.includes('--[[ Deobfuscated') || line.includes('-- Original')) {
            capturing = true;
        }
        if (capturing && (line.includes('return ') || line.includes('function('))) {
            codeLines.push(line);
        }
        if (capturing && line.includes('end') && codeLines.length > 10) {
            capturing = false;
        }
    }
    
    if (codeLines.length > 0) return codeLines.join('\n');
    return null;
}

function extractFromError(stderr) {
    const match = stderr.match(/\[string "([^"]+)"\]/);
    if (match) return match[1];
    return null;
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateLuraph };
