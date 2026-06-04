const { parentPort } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const deobfuscators = {
    moonsec: require('../deobfuscators/moonsec'),
    luaobfuscator: require('../deobfuscators/luaobfuscator'),
    ironbrew: require('../deobfuscators/ironbrew'),
    luraph: require('../deobfuscators/luraph'),
    prometheus: require('../deobfuscators/prometheus'),
    ironveil: require('../deobfuscators/ironveil'),
    boronide: require('../deobfuscators/boronide'),
    star: require('../deobfuscators/star'),
    holylua: require('../deobfuscators/holylua'),
    twenty5ms: require('../deobfuscators/twenty5ms'),
    flamecoder: require('../deobfuscators/flamecoder')
};

parentPort.on('message', async (data) => {
    const { jobId, code, obfuscatorType, userId } = data;
    
    try {
        const deobfuscator = deobfuscators[obfuscatorType];
        if (!deobfuscator) {
            throw new Error(`No deobfuscator for: ${obfuscatorType}`);
        }
        
        const result = await deobfuscator.deobfuscate(code);
        
        parentPort.postMessage({ jobId, output: result });
    } catch (error) {
        parentPort.postMessage({ jobId, error: error.message });
    }
});
