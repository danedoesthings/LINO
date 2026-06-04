async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/Luraph Obfuscator[^\n]*\n/i, '');
    result = result.replace(/local\s+L0\s*=\s*\(\(\(\)\)\)/g, '');
    
    const wrapperPattern = /return\s+function\(([^)]*)\)\s*([\s\S]*?)\s*end\s*$/;
    const match = result.match(wrapperPattern);
    if (match) {
        result = match[2];
    }
    
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    result = result.replace(/_0x[a-f0-9]+/g, 'var');
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    return result;
}

module.exports = { deobfuscate };
