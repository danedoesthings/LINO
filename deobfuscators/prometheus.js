async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/Prometheus Obfuscator[^\n]*\n/i, '');
    result = result.replace(/WeAreDevs[^\n]*\n/i, '');
    
    const returnPattern = /return\(function\(\.\.\.\)local\s+([a-z])\s*=\s*{}([\s\S]*)$/;
    const match = result.match(returnPattern);
    if (match) {
        result = match[2];
    }
    
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let arrMatch;
    while ((arrMatch = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = arrMatch[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                strings.push(JSON.parse(sm));
            }
            const arrayName = arrMatch[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => {
                const index = parseInt(idx);
                return JSON.stringify(strings[index - 1] || 'unknown');
            });
        }
    }
    
    return result;
}

module.exports = { deobfuscate };
