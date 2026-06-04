async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/25ms[^\n]*\n/i, '');
    result = result.replace(/local\s+_25ms\d*\s*=\s*function[^{]*\{/g, 'function(');
    
    result = result.replace(/_25ms[a-zA-Z0-9_]*\(/g, '(');
    result = result.replace(/hookop/g, '');
    
    const pattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*newproxy\(true\)[\s\S]*?setmetatable\([^,]+,\s*{([^}]+)}\)/g;
    result = result.replace(pattern, '');
    
    return result;
}

module.exports = { deobfuscate };
