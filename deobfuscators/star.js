async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/STAR OBFUSCATOR[^\n]*\n/i, '');
    result = result.replace(/--\[\[ STAR[^\]]*\]\]/g, '');
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    
    return result;
}

module.exports = { deobfuscate };
