async function deobfuscate(code) {
    let result = code;
    
    result = result.replace(/Flamecoder[^\n]*\n/i, '');
    result = result.replace(/local\s+_hp_n\s*=\s*0/g, '');
    result = result.replace(/local\s+_hp_m\s*=\s*\d+/g, '');
    
    result = result.replace(/_HOOKOP/g, '');
    result = result.replace(/CHECKIF\(([^,]+),[^)]*\)/g, '$1');
    result = result.replace(/CHECKWHILE\(([^,]+),[^)]*\)/g, '$1');
    result = result.replace(/CHECKAND\(([^,]+),([^,]+),[^)]*\)/g, '$1 and $2');
    result = result.replace(/CHECKOR\(([^,]+),([^,]+),[^)]*\)/g, '$1 or $2');
    
    return result;
}

module.exports = { deobfuscate };
