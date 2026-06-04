const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class LuaBeautifier {
    constructor() {
        this.tempDir = path.join(__dirname, '../temp');
        if (!fs.existsSync(this.tempDir)) fs.mkdirSync(this.tempDir, { recursive: true });
    }
    
    async beautify(code, options = {}) {
        const beautifyOptions = {
            renameVariables: options.renameVariables || false,
            renameGlobals: options.renameGlobals || false,
            solveMath: options.solveMath !== false,
            indentSpaces: options.indentSpaces || 2,
            maxLineLength: options.maxLineLength || 120
        };
        
        let result = code;
        
        result = this.fixIndentation(result, beautifyOptions.indentSpaces);
        result = this.fixLineBreaks(result, beautifyOptions.maxLineLength);
        
        if (beautifyOptions.solveMath) {
            result = this.solveConstantMath(result);
        }
        
        if (beautifyOptions.renameVariables) {
            result = this.renameLocalVariables(result);
        }
        
        result = await this.runExternalBeautifier(result);
        
        return result;
    }
    
    fixIndentation(code, indentSpaces) {
        const lines = code.split('\n');
        const indent = ' '.repeat(indentSpaces);
        let currentIndent = 0;
        const result = [];
        
        for (let line of lines) {
            const trimmed = line.trim();
            if (trimmed === '') {
                result.push('');
                continue;
            }
            
            if (trimmed === 'end' || trimmed === 'until' || trimmed === 'else' || trimmed === 'elseif') {
                currentIndent = Math.max(0, currentIndent - 1);
            }
            
            result.push(indent.repeat(currentIndent) + trimmed);
            
            if (trimmed.endsWith('then') || trimmed.endsWith('do') || trimmed === 'else' || trimmed === 'elseif' || trimmed === 'repeat' || trimmed === 'function(') {
                currentIndent++;
            }
            
            if (trimmed === 'end') {
                currentIndent = Math.max(0, currentIndent);
            }
        }
        
        return result.join('\n');
    }
    
    fixLineBreaks(code, maxLength) {
        const lines = code.split('\n');
        const result = [];
        
        for (let line of lines) {
            if (line.length <= maxLength) {
                result.push(line);
                continue;
            }
            
            const parts = [];
            let current = '';
            let inString = false;
            let stringChar = '';
            
            for (let i = 0; i < line.length; i++) {
                const char = line[i];
                
                if (!inString && (char === '"' || char === "'")) {
                    inString = true;
                    stringChar = char;
                    current += char;
                    continue;
                }
                
                if (inString && char === stringChar && line[i-1] !== '\\') {
                    inString = false;
                    current += char;
                    continue;
                }
                
                current += char;
                
                if (!inString && (char === ',' || char === 'and' || char === 'or')) {
                    if (current.length > maxLength) {
                        parts.push(current);
                        current = indentNextLine(current);
                    }
                }
            }
            
            if (current.length > 0) parts.push(current);
            result.push(parts.join('\n'));
        }
        
        function indentNextLine(line) {
            const match = line.match(/^(\s*)/);
            const spaces = match ? match[1] : '';
            return '\n' + spaces + '  ';
        }
        
        return result.join('\n');
    }
    
    solveConstantMath(code) {
        let result = code;
        
        const mathPatterns = [
            { pattern: /(\d+)\s*\+\s*(\d+)/g, op: (a,b) => a + b },
            { pattern: /(\d+)\s*-\s*(\d+)/g, op: (a,b) => a - b },
            { pattern: /(\d+)\s*\*\s*(\d+)/g, op: (a,b) => a * b },
            { pattern: /(\d+)\s*\/\s*(\d+)/g, op: (a,b) => a / b },
            { pattern: /(\d+)\s*\^\s*(\d+)/g, op: (a,b) => Math.pow(a, b) },
            { pattern: /(\d+)\s*%\s*(\d+)/g, op: (a,b) => a % b }
        ];
        
        for (const { pattern, op } of mathPatterns) {
            result = result.replace(pattern, (_, a, b) => {
                const numA = parseInt(a);
                const numB = parseInt(b);
                if (!isNaN(numA)
