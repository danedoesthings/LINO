class StringDecoder {
    constructor() {
        this.base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    }
    
    decodeBase64(str) {
        str = str.replace(/[^A-Za-z0-9+/=]/g, '');
        
        let binary = '';
        let result = '';
        
        for (let i = 0; i < str.length; i++) {
            const idx = this.base64Chars.indexOf(str[i]);
            if (idx >= 0) {
                binary += idx.toString(2).padStart(6, '0');
            }
        }
        
        for (let i = 0; i < binary.length; i += 8) {
            const byte = binary.slice(i, i + 8);
            if (byte.length === 8) {
                result += String.fromCharCode(parseInt(byte, 2));
            }
        }
        
        return result;
    }
    
    decodeHex(str) {
        if (str.startsWith('0x')) str = str.slice(2);
        let result = '';
        for (let i = 0; i < str.length; i += 2) {
            result += String.fromCharCode(parseInt(str.slice(i, i + 2), 16));
        }
        return result;
    }
    
    decodeOctal(str) {
        const matches = str.match(/\\(\d{1,3})/g);
        if (!matches) return str;
        
        let result = str;
        for (const match of matches) {
            const code = parseInt(match.slice(1), 8);
            result = result.replace(match, String.fromCharCode(code));
        }
        return result;
    }
    
    decodeUnicodeEscape(str) {
        const matches = str.match(/\\u\{([0-9a-fA-F]+)\}/g);
        if (!matches) return str;
        
        let result = str;
        for (const match of matches) {
            const hex = match.match(/\\u\{([0-9a-fA-F]+)\}/)[1];
            const code = parseInt(hex, 16);
            result = result.replace(match, String.fromCodePoint(code));
        }
        return result;
    }
    
    decodeXorString(encoded, key) {
        let result = '';
        for (let i = 0; i < encoded.length; i++) {
            const charCode = encoded.charCodeAt(i) ^ (key.charCodeAt(i % key.length) & 0xFF);
            result += String.fromCharCode(charCode);
        }
        return result;
    }
    
    decodeRot13(str) {
        return str.replace(/[a-zA-Z]/g, (c) => {
            const base = c <= 'Z' ? 65 : 97;
            return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
    }
    
    extractStringPatterns(code) {
        const patterns = {
            base64: /"[A-Za-z0-9+/=]{20,}"/g,
            hex: /"[0-9a-fA-F]{32,}"/g,
            xorEncoded: /"[^"]*"\s*\^\s*\d+/g,
            octalEscapes: /\\\d{1,3}/g,
            unicodeEscapes: /\\u\{[0-9a-fA-F]+\}/g
        };
        
        const results = {
            base64: [],
            hex: [],
            xor: [],
            octal: [],
            unicode: []
        };
        
        for (const [type, pattern] of Object.entries(patterns)) {
            const matches = code.match(pattern);
            if (matches) {
                results[type] = matches.map(m => m.slice(1, -1));
            }
        }
        
        return results;
    }
    
    attemptDecodeAll(encoded) {
        const results = [];
        
        try {
            results.push({ method: 'base64', result: this.decodeBase64(encoded) });
        } catch (e) {}
        
        try {
            results.push({ method: 'hex', result: this.decodeHex(encoded) });
        } catch (e) {}
        
        try {
            results.push({ method: 'octal', result: this.decodeOctal(encoded) });
        } catch (e) {}
        
        try {
            results.push({ method: 'unicode', result: this.decodeUnicodeEscape(encoded) });
        } catch (e) {}
        
        for (let key = 1; key <= 255; key++) {
            try {
                const decoded = this.decodeXorString(encoded, String.fromCharCode(key));
                if (/^[a-zA-Z0-9\s\p{P}]/u.test(decoded.slice(0, 20))) {
                    results.push({ method: `xor_${key}`, result: decoded });
                }
            } catch (e) {}
        }
        
        results.sort((a, b) => b.result.length - a.result.length);
        
        return results;
    }
}

module.exports = StringDecoder;
