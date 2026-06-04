const { Client, GatewayIntentBits, Partials, EmbedBuilder, AttachmentBuilder } = require('discord.js');
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages
    ],
    partials: [Partials.Channel]
});

function loadDeobfuscator(name) {
    try {
        return require(`./deobfuscators/${name}`);
    } catch (e) {
        console.log(`Failed to load ${name}, using fallback`);
        return { deobfuscate: async (code) => code };
    }
}

const deobfuscators = {
    moonsec: loadDeobfuscator('moonsec'),
    luaobfuscator: loadDeobfuscator('luaobfuscator'),
    ironbrew: loadDeobfuscator('ironbrew'),
    luraph: loadDeobfuscator('luraph'),
    prometheus: loadDeobfuscator('prometheus'),
    ironveil: loadDeobfuscator('ironveil'),
    boronide: loadDeobfuscator('boronide'),
    star: loadDeobfuscator('star'),
    holylua: loadDeobfuscator('holylua'),
    twenty5ms: loadDeobfuscator('twenty5ms'),
    flamecoder: loadDeobfuscator('flamecoder')
};

console.log('Loaded deobfuscators:', Object.keys(deobfuscators));

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
        if (sig.pattern.test(code)) {
            return sig.name;
        }
    }
    return 'unknown';
}

function extractCodeBlock(content) {
    const codeblockRegex = /```(?:lua|luau)?\n?([\s\S]*?)```/i;
    const match = content.match(codeblockRegex);
    if (match) return match[1].trim();
    
    const inlineCodeRegex = /`([^`]+)`/;
    const inlineMatch = content.match(inlineCodeRegex);
    if (inlineMatch) return inlineMatch[1].trim();
    
    return null;
}

async function fetchFromUrl(url) {
    try {
        const response = await axios.get(url, { 
            timeout: 15000,
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        return response.data;
    } catch (error) {
        throw new Error(`Failed to fetch URL: ${error.message}`);
    }
}

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
            .setDescription('Commands:\n.deobf <code> - Auto-detect and deobfuscate\n.detect <code> - Detect obfuscator type\n.status - Bot status')
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
    
    if (!obfuscatorType) return;
    
    const userInput = content.slice(content.indexOf(' ')).trim();
    
    let scriptCode = extractCodeBlock(userInput);
    
    if (!scriptCode && userInput.match(/^https?:\/\//i)) {
        try {
            scriptCode = await fetchFromUrl(userInput);
        } catch (error) {
            await message.reply(`Failed to fetch URL: ${error.message}`);
            return;
        }
    }
    
    if (!scriptCode && message.attachments.size > 0) {
        const attachment = message.attachments.first();
        try {
            const response = await axios.get(attachment.url, { responseType: 'text' });
            scriptCode = response.data;
        } catch (error) {
            await message.reply(`Failed to download attachment: ${error.message}`);
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
            await message.reply('Could not auto-detect obfuscator type. Please specify manually.');
            return;
        }
    }
    
    const statusMsg = await message.reply(`Deobfuscating ${obfuscatorType} script...`);
    
    try {
        const deobfuscator = deobfuscators[obfuscatorType];
        const result = await deobfuscator.deobfuscate(scriptCode);
        
        const outputFileName = `deobfuscated_${Date.now()}.lua`;
        const attachment = new AttachmentBuilder(Buffer.from(result, 'utf8'), { name: outputFileName });
        
        await statusMsg.delete();
        
        const embed = new EmbedBuilder()
            .setTitle('Deobfuscation Complete')
            .setColor(0x00ff00)
            .addFields(
                { name: 'Obfuscator', value: obfuscatorType, inline: true },
                { name: 'Size', value: `${(result.length / 1024).toFixed(2)} KB`, inline: true }
            );
        
        await message.reply({ embeds: [embed], files: [attachment] });
        
    } catch (error) {
        await statusMsg.edit(`Deobfuscation failed: ${error.message}`);
    }
});

client.login(process.env.DISCORD_TOKEN);
