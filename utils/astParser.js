const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ASTParser {
    constructor() {
        this.tempDir = path.join(__dirname, '../temp');
        if (!fs.existsSync(this.tempDir)) fs.mkdirSync(this.tempDir, { recursive: true });
    }
    
    async parseLuaToAST(code) {
        const inputFile = path.join(this.tempDir, `${crypto.randomBytes(8).toString('hex')}.lua`);
        fs.writeFileSync(inputFile, code, 'utf8');
        
        return new Promise((resolve, reject) => {
            const luauAnalyze = spawn('luau-analyze', [inputFile]);
            
            let stdout = '', stderr = '';
            luauAnalyze.stdout.on('data', (data) => { stdout += data.toString(); });
            luauAnalyze.stderr.on('data', (data) => { stderr += data.toString(); });
            
            luauAnalyze.on('close', (code) => {
                fs.unlinkSync(inputFile);
                if (stdout) {
                    resolve(this.parseAnalysisOutput(stdout));
                } else {
                    reject(new Error(stderr || 'AST parsing failed'));
                }
            });
        });
    }
    
    parseAnalysisOutput(output) {
        const ast = {
            type: 'Chunk',
            body: [],
            comments: []
        };
        
        const lines = output.split('\n');
        let currentDepth = 0;
        let currentBlock = ast;
        
        for (const line of lines) {
            if (line.includes('function') && !line.includes('end')) {
                const funcName = line.match(/function\s+([a-zA-Z_][a-zA-Z0-9_]*)/);
                if (funcName) {
                    const funcNode = {
                        type: 'FunctionDeclaration',
                        name: funcName[1],
                        body: []
                    };
                    if (currentBlock.body) currentBlock.body.push(funcNode);
                    currentBlock = funcNode;
                    currentDepth++;
                }
            }
            
            if (line.includes('end') && currentDepth > 0) {
                if (currentBlock.parent) {
                    currentBlock = currentBlock.parent;
                }
                currentDepth--;
            }
        }
        
        return ast;
    }
    
    extractFunctions(code) {
        const functions = [];
        const pattern = /function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*([\s\S]*?)\s*end/g;
        let match;
        
        while ((match = pattern.exec(code)) !== null) {
            functions.push({
                name: match[1],
                params: this.parseParams(match[2]),
                body: match[3]
            });
        }
        
        return functions;
    }
    
    parseParams(paramString) {
        if (!paramString.trim()) return [];
        return paramString.split(',').map(p => p.trim());
    }
    
    extractVariables(code) {
        const variables = new Map();
        const localPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;\n]+)/g;
        let match;
        
        while ((match = localPattern.exec(code)) !== null) {
            variables.set(match[1], {
                type: 'local',
                value: match[2].trim(),
                line: this.getLineNumber(code, match.index)
            });
        }
        
        return variables;
    }
    
    getLineNumber(code, position) {
        return code.substring(0, position).split('\n').length;
    }
}

module.exports = ASTParser;
