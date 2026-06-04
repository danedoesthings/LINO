const { Client, GatewayIntentBits, Partials, EmbedBuilder, AttachmentBuilder } = require('discord.js');
require('dotenv').config();
const axios = require('axios');
const crypto = require('crypto');

const token = process.env.DISCORD_TOKEN;
if (!token) {
    console.error('FATAL: DISCORD_TOKEN environment variable is not set!');
    process.exit(1);
}

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages
    ],
    partials: [Partials.Channel]
});

// ==================== DEOBFUSCATION FUNCTIONS ====================

function deobfuscateMoonsec(code) {
    let result = code;
    result = result.replace(/local\s+_ENV\s*=\s*setmetatable\([^,]+,\s*{[^}]+}\)/g, '');
    result = result.replace(/getfenv\(\)\._ENV\s*=\s*getfenv\(\)/g, '');
    result = result.replace(/local\s+_0x[a-f0-9]+\s*=\s*{[^}]+}/g, '');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let match;
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                try {
                    let cleaned = sm.slice(1, -1);
                    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, (hex) => String.fromCharCode(parseInt(hex.slice(2), 16)));
                    cleaned = cleaned.replace(/\\\d{1,3}/g, (oct) => String.fromCharCode(parseInt(oct.slice(1), 8)));
                    strings.push(cleaned);
                } catch { strings.push(sm.slice(1, -1)); }
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => {
                const index = parseInt(idx);
                const str = strings[index - 1] || 'unknown';
                return JSON.stringify(str);
            });
        }
    }
    
    result = result.replace(/bit32\.bxor\((\d+),\s*(\d+)\)/g, (_, a, b) => String(parseInt(a) ^ parseInt(b)));
    result = result.replace(/\\x[0-9a-fA-F]{2}/g, (m) => { try { return String.fromCharCode(parseInt(m.slice(2), 16)); } catch { return m; } });
    result = result.replace(/\\\d{1,3}/g, (m) => { try { return String.fromCharCode(parseInt(m.slice(1), 8)); } catch { return m; } });
    return result;
}

function deobfuscateLuaObfuscator(code) {
    let result = code;
    result = result.replace(/LuaObfuscator\.com[^\n]*\n/, '');
    result = result.replace(/local\s+_0x[a-f0-9]+\s*=\s*\{[^}]+\}/g, '');
    
    const stringDecryptPattern = /_0x([a-f0-9]+)\(["']([^"']+)["']\)/g;
    result = result.replace(stringDecryptPattern, (_, id, str) => {
        let decoded = str;
        try {
            if (str.match(/^[0-9a-fA-F]+$/)) {
                decoded = '';
                for (let i = 0; i < str.length; i += 2) decoded += String.fromCharCode(parseInt(str.slice(i, i + 2), 16));
            }
        } catch {}
        return JSON.stringify(decoded);
    });
    
    result = result.replace(/_0x[a-f0-9]+/g, 'var');
    result = result.replace(/bit32\.bxor\((\d+),\s*(\d+)\)/g, (_, a, b) => String(parseInt(a) ^ parseInt(b)));
    result = result.replace(/\\x[0-9a-fA-F]{2}/g, (m) => { try { return String.fromCharCode(parseInt(m.slice(2), 16)); } catch { return m; } });
    return result;
}

function deobfuscateIronbrew(code) {
    let result = code;
    result = result.replace(/IronBrew[^\n]*\n/i, '');
    result = result.replace(/local\s+Il1l1l1l1l1l1l1l\s*=\s*{[^}]+}/g, '');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let match;
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                try {
                    let cleaned = sm.slice(1, -1);
                    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, (hex) => String.fromCharCode(parseInt(hex.slice(2), 16)));
                    strings.push(cleaned);
                } catch { strings.push(sm.slice(1, -1)); }
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => JSON.stringify(strings[parseInt(idx) - 1] || 'unknown'));
        }
    }
    
    result = result.replace(/bit32\.bxor\((\d+),\s*(\d+)\)/g, (_, a, b) => String(parseInt(a) ^ parseInt(b)));
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    return result;
}

function deobfuscateLuraph(code) {
    let result = code;
    result = result.replace(/Luraph Obfuscator[^\n]*\n/i, '');
    result = result.replace(/local\s+L0\s*=\s*\(\(\(\)\)\)/g, '');
    
    const wrapperPattern = /return\s+function\(([^)]*)\)\s*([\s\S]*?)\s*end\s*$/;
    const match = result.match(wrapperPattern);
    if (match) result = match[2];
    
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    result = result.replace(/_0x[a-f0-9]+/g, 'var');
    result = result.replace(/bit32\.bxor\((\d+),\s*(\d+)\)/g, (_, a, b) => String(parseInt(a) ^ parseInt(b)));
    return result;
}

function deobfuscatePrometheus(code) {
    let result = code;
    result = result.replace(/Prometheus Obfuscator[^\n]*\n/i, '');
    result = result.replace(/WeAreDevs[^\n]*\n/i, '');
    
    const returnPattern = /return\(function\(\.\.\.\)local\s+([a-z])\s*=\s*{}([\s\S]*)$/;
    const match = result.match(returnPattern);
    if (match) result = match[2];
    
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let arrMatch;
    while ((arrMatch = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = arrMatch[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                try {
                    let cleaned = sm.slice(1, -1);
                    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, (hex) => String.fromCharCode(parseInt(hex.slice(2), 16)));
                    strings.push(cleaned);
                } catch { strings.push(sm.slice(1, -1)); }
            }
            const arrayName = arrMatch[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => JSON.stringify(strings[parseInt(idx) - 1] || 'unknown'));
        }
    }
    return result;
}

function deobfuscateIronveil(code) {
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
                try {
                    let cleaned = sm.slice(1, -1);
                    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, (hex) => String.fromCharCode(parseInt(hex.slice(2), 16)));
                    strings.push(cleaned);
                } catch { strings.push(sm.slice(1, -1)); }
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => JSON.stringify(strings[parseInt(idx) - 1] || 'unknown'));
        }
    }
    
    result = result.replace(/bit32\.bxor\((\d+),\s*(\d+)\)/g, (_, a, b) => String(parseInt(a) ^ parseInt(b)));
    return result;
}

function deobfuscateBoronide(code) {
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
                try {
                    let cleaned = sm.slice(1, -1);
                    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, (hex) => String.fromCharCode(parseInt(hex.slice(2), 16)));
                    strings.push(cleaned);
                } catch { strings.push(sm.slice(1, -1)); }
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => JSON.stringify(strings[parseInt(idx) - 1] || 'unknown'));
        }
    }
    return result;
}

function deobfuscateStar(code) {
    let result = code;
    result = result.replace(/STAR OBFUSCATOR[^\n]*\n/i, '');
    result = result.replace(/--\[\[ STAR[^\]]*\]\]/g, '');
    result = result.replace(/bit32\.bxor\((\d+),\s*(\d+)\)/g, (_, a, b) => String(parseInt(a) ^ parseInt(b)));
    result = result.replace(/local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)[^{]*\{/g, 'function(');
    return result;
}

function deobfuscateHolyLua(code) {
    let result = code;
    result = result.replace(/--\[\[holylua[^\]]*\]\]/gi, '');
    result = result.replace(/holylua\s*=\s*{[^}]+}/gi, '');
    
    const stringArrayPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*{((?:[^,}]+,?)+)}/g;
    let match;
    while ((match = stringArrayPattern.exec(result)) !== null) {
        const strings = [];
        const content = match[2];
        const strMatches = content.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
        if (strMatches) {
            for (const sm of strMatches) {
                try {
                    let cleaned = sm.slice(1, -1);
                    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, (hex) => String.fromCharCode(parseInt(hex.slice(2), 16)));
                    strings.push(cleaned);
                } catch { strings.push(sm.slice(1, -1)); }
            }
            const arrayName = match[1];
            const accessPattern = new RegExp(`${arrayName}\\[(\\d+)\\]`, 'g');
            result = result.replace(accessPattern, (_, idx) => JSON.stringify(strings[parseInt(idx) - 1] || 'unknown'));
        }
    }
    return result;
}

function deobfuscateTwenty5ms(code) {
    let result = code;
    result = result.replace(/25ms[^\n]*\n/i, '');
    result = result.replace(/local\s+_25ms\d*\s*=\s*function[^{]*\{/g, 'function(');
    result = result.replace(/_25ms[a-zA-Z0-9_]*\(/g, '(');
    result = result.replace(/hookop/g, '');
    
    const pattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*newproxy\(true\)[\s\S]*?setmetatable\([^,]+,\s*{([^}]+)}\)/g;
    result = result.replace(pattern, '');
    return result;
}

function deobfuscateFlamecoder(code) {
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

function detectObfuscator(code) {
    const signatures = [
        { name: 'moonsec', pattern: /MoonSec|local _ENV=setmetatable/i },
        { name: 'luaobfuscator', pattern: /LuaObfuscator\.com|_0x[a-f0-9]+/i },
        { name: 'ironbrew', pattern: /IronBrew|Il1l1l1l1l1l1l1l/i },
        { name: 'luraph', pattern: /Luraph/i },
        { name: 'prometheus', pattern: /Prometheus|WeAreDevs/i },
        { name: 'ironveil', pattern: /ironveil|IronVeil/i },
        { name: 'boronide', pattern: /Boronide|Hercules/i },
        { name: 'star', pattern: /STAR OBFUSCATOR/i },
        { name: 'holylua', pattern: /holylua|HolyLua/i },
        { name: 'twenty5ms', pattern: /25ms|_25ms/i },
        { name: 'flamecoder', pattern: /Flamecoder|_HOOKOP/i }
    ];
    for (const sig of signatures) {
        if (sig.pattern.test(code)) return sig.name;
    }
    return 'unknown';
}

function extractCodeBlock(content) {
    const match = content.match(/```(?:lua|luau)?\n?([\s\S]*?)```/i);
    if (match) return match[1].trim();
    const inlineMatch = content.match(/`([^`]+)`/);
    if (inlineMatch) return inlineMatch[1].trim();
    return null;
}

async function fetchFromUrl(url) {
    const response = await axios.get(url, { timeout: 15000, headers: { 'User-Agent': 'Mozilla/5.0' } });
    return response.data;
}

const deobfuscators = {
    moonsec: deobfuscateMoonsec,
    luaobfuscator: deobfuscateLuaObfuscator,
    ironbrew: deobfuscateIronbrew,
    luraph: deobfuscateLuraph,
    prometheus: deobfuscatePrometheus,
    ironveil: deobfuscateIronveil,
    boronide: deobfuscateBoronide,
    star: deobfuscateStar,
    holylua: deobfuscateHolyLua,
    twenty5ms: deobfuscateTwenty5ms,
    flamecoder: deobfuscateFlamecoder
};

client.once('ready', () => {
    console.log(`Logged in as ${client.user.tag}`);
    console.log(`Loaded ${Object.keys(deobfuscators).length} deobfuscators`);
});

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    const content = message.content;
    
    if (content === '.help') {
        const embed = new EmbedBuilder()
            .setTitle('Lua Deobfuscation Bot')
            .setDescription('Commands:\n.deobf <code> - Auto-detect and deobfuscate\n.detect <code> - Detect obfuscator type\n.status - Bot status\n\nSpecific obfuscators: .moonsec, .luaobf, .ironbrew, .luraph, .prometheus')
            .setColor(0x00ff00);
        await message.reply({ embeds: [embed] });
        return;
    }
    
    if (content === '.status') {
        const embed = new EmbedBuilder()
            .setTitle('Bot Status')
            .setColor(0x00ff00)
            .addFields(
                { name: 'Deobfuscators', value: `${Object.keys(deobfuscators).length}`, inline: true },
                { name: 'Node Version', value: process.version, inline: true }
            );
        await message.reply({ embeds: [embed] });
        return;
    }
    
    let obfuscatorType = null;
    if (content.startsWith('.moonsec')) obfuscatorType = 'moonsec';
    else if (content.startsWith('.luaobf')) obfuscatorType = 'luaobfuscator';
    else if (content.startsWith('.ironbrew')) obfuscatorType = 'ironbrew';
    else if (content.startsWith('.luraph')) obfuscatorType = 'luraph';
    else if (content.startsWith('.prometheus')) obfuscatorType = 'prometheus';
    else if (content.startsWith('.deobf')) obfuscatorType = 'auto';
    else return;
    
    const userInput = content.slice(content.indexOf(' ') + 1).trim();
    let scriptCode = extractCodeBlock(userInput);
    
    if (!scriptCode && userInput.match(/^https?:\/\//i)) {
        try {
            scriptCode = await fetchFromUrl(userInput);
        } catch (err) {
            await message.reply(`Failed to fetch URL: ${err.message}`);
            return;
        }
    }
    
    if (!scriptCode && message.attachments.size > 0) {
        const attachment = message.attachments.first();
        try {
            const response = await axios.get(attachment.url, { responseType: 'text' });
            scriptCode = response.data;
        } catch (err) {
            await message.reply(`Failed to download attachment: ${err.message}`);
            return;
        }
    }
    
    if (!scriptCode) {
        await message.reply('Please provide Lua code in a code block, as a file attachment, or as a URL.');
        return;
    }
    
    if (scriptCode.length > 5000000) {
        await message.reply('File too large (max 5MB).');
        return;
    }
    
    if (obfuscatorType === 'auto') {
        obfuscatorType = detectObfuscator(scriptCode);
        if (obfuscatorType === 'unknown') {
            await message.reply('Could not auto-detect obfuscator type. Please specify manually using .moonsec, .luaobf, .ironbrew, .luraph, or .prometheus');
            return;
        }
    }
    
    const statusMsg = await message.reply(`Deobfuscating ${obfuscatorType} script...`);
    
    try {
        const deobfuscateFn = deobfuscators[obfuscatorType];
        let result = deobfuscateFn(scriptCode);
        if (result.length < 100) result = '# Deobfuscation produced minimal output\n\n' + result;
        
        const attachment = new AttachmentBuilder(Buffer.from(result, 'utf8'), { name: `deobfuscated_${Date.now()}.lua` });
        const embed = new EmbedBuilder()
            .setTitle('Deobfuscation Complete')
            .setColor(0x00ff00)
            .addFields(
                { name: 'Obfuscator', value: obfuscatorType, inline: true },
                { name: 'Output Size', value: `${(result.length / 1024).toFixed(2)} KB`, inline: true }
            );
        await statusMsg.delete();
        await message.reply({ embeds: [embed], files: [attachment] });
    } catch (err) {
        console.error(err);
        await statusMsg.edit(`Deobfuscation failed: ${err.message}`);
    }
});

client.login(token);
