async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/Boronide[^\n]*\n/i, '');
    result = result.replace(/Hercules Obfuscator[^\n]*\n/i, '');
    
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
    
    return result;
}

module.exports = { deobfuscate };
