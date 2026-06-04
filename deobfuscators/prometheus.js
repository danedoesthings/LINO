const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscatePrometheus(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_decrypted.lua`);
    
    return new Promise((resolve, reject) => {
        const luaProcess = spawn('lua', [
            path.join(__dirname, '../scripts/prometheus_decrypt.lua'),
            inputFile,
            outputFile
        ]);
        
        let stdout = '', stderr = '';
        luaProcess.stdout.on('data', (data) => { stdout += data.toString(); });
        luaProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
        luaProcess.on('close', (code) => {
            cleanup(inputFile, outputFile);
            
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                resolve(result);
            } else if (stdout.includes('success') || stdout.includes('Done')) {
                const extracted = extractStringsFromOutput(stdout);
                if (extracted) resolve(extracted);
                else reject(new Error('Failed to extract deobfuscated code'));
            } else {
                reject(new Error(`Prometheus deobfuscation failed: ${stderr || stdout || 'Unknown error'}`));
            }
        });
        
        luaProcess.on('error', (err) => {
            cleanup(inputFile, outputFile);
            reject(err);
        });
    });
}

function extractStringsFromOutput(output) {
    const lines = output.split('\n');
    const codeLines = [];
    let inCode = false;
    
    for (const line of lines) {
        if (line.includes('--[[ Deobfuscated') || line.includes('-- Generated')) {
            inCode = true;
        }
        if (inCode && !line.includes('Decrypting') && !line.includes('string')) {
            codeLines.push(line);
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

module.exports = { deobfuscate: deobfuscatePrometheus };
