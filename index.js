const { Client, GatewayIntentBits, Partials, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, AttachmentBuilder, StringSelectMenuBuilder, StringSelectMenuOptionBuilder } = require('discord.js');
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const crypto = require('crypto');

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages
    ],
    partials: [Partials.Channel]
});

const deobfuscators = {
    moonsec: require('./deobfuscators/moonsec'),
    luaobfuscator: require('./deobfuscators/luaobfuscator'),
    ironbrew: require('./deobfuscators/ironbrew'),
    luraph: require('./deobfuscators/luraph'),
    prometheus: require('./deobfuscators/prometheus'),
    ironveil: require('./deobfuscators/ironveil'),
    boronide: require('./deobfuscators/boronide'),
    star: require('./deobfuscators/star'),
    holylua: require('./deobfuscators/holylua'),
    twenty5ms: require('./deobfuscators/twenty5ms'),
    flamecoder: require('./deobfuscators/flamecoder')
};

const activeJobs = new Map();
const workerPool = [];
const MAX_WORKERS = 4;

for (let i = 0; i < MAX_WORKERS; i++) {
    const worker = new Worker('./workers/processor.js');
    workerPool.push(worker);
}

function getAvailableWorker() {
    for (let i = 0; i < workerPool.length; i++) {
        if (!activeJobs.has(workerPool[i].threadId)) {
            return workerPool[i];
        }
    }
    return null;
}

function detectObfuscator(code) {
    const signatures = {
        moonsec: /This file was protected with MoonSec|MoonSec V3|local _ENV=setmetatable|function\(\.\.\.\)local [a-z]={/i,
        luaobfuscator: /LuaObfuscator\.com|local _0x[a-f0-9]+|local function\(\)local [a-z]="\\[0-9]+"/i,
        ironbrew: /IronBrew|local Il1l1l1l1l1l1l1l|local function oOOo0O0oO0oO0o/i,
        luraph: /Luraph Obfuscator|local L0=[(][(][)]|local function L0O0O0O0O0O0O/i,
        prometheus: /Prometheus Obfuscator|WeAreDevs|return\(function\(\.\.\.\)local [a-z]={}/i,
        ironveil: /ironveil|IronVeil|local function 0o0Oo0o0O0o/i,
        boronide: /Boronide|Hercules Obfuscator|local function Boronide/i,
        star: /STAR OBFUSCATOR|Star Obfuscator|local function Star/i,
        holylua: /holylua|HolyLua|--\[\[holylua/i,
        twenty5ms: /25ms|_25ms\d+|local _25ms|hookop/i,
        flamecoder: /Flamecoder|_HOOKOP|local _hp_n/,
        unknown: null
    };
    
    for (const [name, pattern] of Object.entries(signatures)) {
        if (pattern && pattern.test(code)) {
            return name;
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
    const axios = require('axios');
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

async function processDeobfuscation(code, obfuscatorType, userId) {
    return new Promise((resolve, reject) => {
        const worker = getAvailableWorker();
        if (!worker) {
            reject(new Error('No workers available. Please try again later.'));
            return;
        }
        
        const jobId = crypto.randomBytes(8).toString('hex');
        activeJobs.set(worker.threadId, { resolve, reject, timeout: null });
        
        const timeout = setTimeout(() => {
            if (activeJobs.has(worker.threadId)) {
                activeJobs.delete(worker.threadId);
                reject(new Error('Deobfuscation timeout exceeded (120 seconds).'));
            }
        }, 120000);
        
        activeJobs.get(worker.threadId).timeout = timeout;
        
        worker.postMessage({ jobId, code, obfuscatorType, userId });
        
        worker.once('message', (result) => {
            if (activeJobs.has(worker.threadId)) {
                clearTimeout(activeJobs.get(worker.threadId).timeout);
                activeJobs.delete(worker.threadId);
            }
            if (result.error) {
                reject(new Error(result.error));
            } else {
                resolve(result.output);
            }
        });
    });
}

client.once('ready', () => {
    console.log(`Logged in as ${client.user.tag}`);
    console.log(`Loaded ${Object.keys(deobfuscators).length} deobfuscators`);
});

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    
    const content = message.content;
    const isDM = message.channel.type === 1;
    
    if (content === '.help' || content === '.commands') {
        const embed = new EmbedBuilder()
            .setTitle('Lua Deobfuscation Bot')
            .setDescription('Advanced deobfuscation for various Lua obfuscators')
            .setColor(0x00ff00)
            .addFields(
                { name: '.deobf <code/file/link>', value: 'Auto-detect and deobfuscate', inline: false },
                { name: '.detect <code>', value: 'Detect obfuscator type', inline: false },
                { name: '.moonsec <code>', value: 'Moonsec V3 deobfuscation', inline: true },
                { name: '.luaobf <code>', value: 'LuaObfuscator.com deobf', inline: true },
                { name: '.ironbrew <code>', value: 'Ironbrew 2 deobf', inline: true },
                { name: '.luraph <code>', value: 'Luraph deobfuscation', inline: true },
                { name: '.prometheus <code>', value: 'Prometheus/WeAreDevs deobf', inline: true },
                { name: '.ironveil <code>', value: 'IronVeil deobfuscation', inline: true },
                { name: '.status', value: 'Check bot status', inline: false }
            )
            .setFooter({ text: 'Deobfuscation may take 30-120 seconds' });
        
        await message.reply({ embeds: [embed] });
        return;
    }
    
    if (content === '.status') {
        const embed = new EmbedBuilder()
            .setTitle('Bot Status')
            .setColor(0x00ff00)
            .addFields(
                { name: 'Workers', value: `${workerPool.filter(w => !activeJobs.has(w.threadId)).length}/${MAX_WORKERS} available`, inline: true },
                { name: 'Active Jobs', value: `${activeJobs.size}`, inline: true },
                { name: 'Deobfuscators', value: `${Object.keys(deobfuscators).length}`, inline: true }
            );
        await message.reply({ embeds: [embed] });
        return;
    }
    
    if (content === '.detect') {
        await message.reply('Please provide code to detect. Example: `.detect \\`\\`\\`lua your code here \\`\\`\\``');
        return;
    }
    
    let command = null;
    let obfuscatorType = null;
    
    if (content.startsWith('.moonsec')) { command = '.moonsec'; obfuscatorType = 'moonsec'; }
    else if (content.startsWith('.luaobf')) { command = '.luaobf'; obfuscatorType = 'luaobfuscator'; }
    else if (content.startsWith('.ironbrew')) { command = '.ironbrew'; obfuscatorType = 'ironbrew'; }
    else if (content.startsWith('.luraph')) { command = '.luraph'; obfuscatorType = 'luraph'; }
    else if (content.startsWith('.prometheus')) { command = '.prometheus'; obfuscatorType = 'prometheus'; }
    else if (content.startsWith('.ironveil')) { command = '.ironveil'; obfuscatorType = 'ironveil'; }
    else if (content.startsWith('.boronide')) { command = '.boronide'; obfuscatorType = 'boronide'; }
    else if (content.startsWith('.star')) { command = '.star'; obfuscatorType = 'star'; }
    else if (content.startsWith('.holylua')) { command = '.holylua'; obfuscatorType = 'holylua'; }
    else if (content.startsWith('.25ms')) { command = '.25ms'; obfuscatorType = 'twenty5ms'; }
    else if (content.startsWith('.flamecoder')) { command = '.flamecoder'; obfuscatorType = 'flamecoder'; }
    else if (content.startsWith('.deobf')) { command = '.deobf'; obfuscatorType = 'auto'; }
    
    if (!command) return;
    
    const userInput = content.slice(command.length).trim();
    
    let scriptCode = extractCodeBlock(userInput);
    
    if (!scriptCode && userInput.match(/^https?:\/\//i)) {
        const statusMsg = await message.reply('Fetching from URL...');
        try {
            scriptCode = await fetchFromUrl(userInput);
            await statusMsg.delete();
        } catch (error) {
            await message.reply(`Failed to fetch URL: ${error.message}`);
            return;
        }
    }
    
    if (!scriptCode && message.attachments.size > 0) {
        const attachment = message.attachments.first();
        if (attachment.name.endsWith('.lua') || attachment.name.endsWith('.luau') || attachment.name.endsWith('.txt')) {
            const statusMsg = await message.reply('Downloading attachment...');
            try {
                const response = await fetch(attachment.url);
                scriptCode = await response.text();
                await statusMsg.delete();
            } catch (error) {
                await message.reply(`Failed to download attachment: ${error.message}`);
                return;
            }
        }
    }
    
    if (!scriptCode) {
        await message.reply('Please provide Lua code in a code block, as a file attachment, or as a URL.');
        return;
    }
    
    if (scriptCode.length > 5000000) {
        await message.reply('File too large (max 5MB). Please provide a smaller file.');
        return;
    }
    
    if (obfuscatorType === 'auto') {
        obfuscatorType = detectObfuscator(scriptCode);
        if (obfuscatorType === 'unknown') {
            await message.reply('Could not auto-detect obfuscator type. Please specify manually using one of the specific commands.');
            return;
        }
    }
    
    const statusMsg = await message.reply(`Deobfuscating ${obfuscatorType} script... This may take up to 120 seconds.`);
    
    try {
        const deobfuscator = deobfuscators[obfuscatorType];
        if (!deobfuscator) {
            await statusMsg.edit(`No deobfuscator available for: ${obfuscatorType}`);
            return;
        }
        
        const result = await deobfuscator.deobfuscate(scriptCode);
        
        const outputFileName = `deobfuscated_${Date.now()}.lua`;
        const outputBuffer = Buffer.from(result, 'utf8');
        const attachment = new AttachmentBuilder(outputBuffer, { name: outputFileName });
        
        await statusMsg.delete();
        
        const embed = new EmbedBuilder()
            .setTitle('Deobfuscation Complete')
            .setColor(0x00ff00)
            .addFields(
                { name: 'Obfuscator', value: obfuscatorType, inline: true },
                { name: 'Input Size', value: `${(scriptCode.length / 1024).toFixed(2)} KB`, inline: true },
                { name: 'Output Size', value: `${(result.length / 1024).toFixed(2)} KB`, inline: true }
            );
        
        await message.reply({ embeds: [embed], files: [attachment] });
        
    } catch (error) {
        console.error(`Deobfuscation error for ${obfuscatorType}:`, error);
        await statusMsg.edit(`Deobfuscation failed: ${error.message || 'Unknown error'}`);
    }
});

client.login(process.env.DISCORD_TOKEN);
