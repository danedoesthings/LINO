async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/ironveil[^\n]*\n/i, '');
    result = result.replace(/IronVeil[^\n]*\n/i, '');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let match;
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                strings.push(JSON.parse(sm));
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => {
                const index = parseInt(idx);
                return JSON.stringify(strings[index - 1] || 'unknown');
            });
        }
    }
    
    const xorPattern = /bit32\.bxor\((\d+),\s*(\d+)\)/g;
    result = result.replace(xorPattern, (_, a, b) => {
        return String(parseInt(a) ^ parseInt(b));
    });
    
    return result;
}

module.exports = { deobfuscate };
