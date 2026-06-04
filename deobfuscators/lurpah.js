const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

async function deobfuscateIronVeil(code) {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    
    const inputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
    fs.writeFileSync(inputFile, code, 'utf8');
    
    const outputFile = path.join(tempDir, `${crypto.randomBytes(8).toString('hex')}_deobf.lua`);
    
    return new Promise((resolve, reject) => {
        const nodeProcess = spawn('node', [
            path.join(__dirname, '../node_modules/ironveil-deobf/deobfuscator/index.js'),
            inputFile,
            outputFile
        ]);
        
        let stderr = '';
        nodeProcess.stderr.on('data', (data) => { stderr += data.toString(); });
        
        nodeProcess.on('close', (code) => {
            if (fs.existsSync(outputFile)) {
                const result = fs.readFileSync(outputFile, 'utf8');
                cleanup(inputFile, outputFile);
                resolve(result);
            } else {
                const extracted = extractFromOutput(stderr);
                cleanup(inputFile, outputFile);
                if (extracted) resolve(extracted);
                else reject(new Error('IronVeil deobfuscation failed'));
            }
        });
    });
}

function extractFromOutput(output) {
    const lines = output.split('\n');
    const codeLines = [];
    let inCode = false;
    
    for (const line of lines) {
        if (line.includes('Successfully deobfuscated')) {
            inCode = true;
        }
        if (inCode && line.trim().startsWith('-- deobfuscated')) {
            codeLines.push(line);
        }
        if (inCode && line.trim().length > 0 && !line.includes('ironveil')) {
            codeLines.push(line);
        }
    }
    
    return codeLines.length > 0 ? codeLines.join('\n') : null;
}

function cleanup(...files) {
    for (const file of files) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
}

module.exports = { deobfuscate: deobfuscateIronVeil };
