const proxy = "http://CnUvt9XpMADgyJq:IEm97oGXASdTlQv@156.232.90.75:44282"
const requestPromise = require('request-promise')

const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')
const numset = '0123456789'.split('')

const random = (x = 0, y = 1) => Math.floor(Math.random() * (y - x + 1)) + x;
const generateId = (len, numbersOnly) => {
    const set = numbersOnly ? charset : numset
    let r = '';
    for (let i = 0; i < len; i++) {
        r += set[random(0, set.length - 1)]
    }
    return r
}

const request = async (url) => {
    try {
        const content = await requestPromise({
            url: url,
            proxy: proxy,
            method: "GET",
            headers: url.match(/https:\/\/\w+\.roblox\.com/) ? undefined : {
                "traceparent": `00-${generateId(49)}-00`,
                "Roblox-Id": generateId(16, true), // probably randomize ts later (1/31: is it not already randomized?)
                "User-Agent": `Roblox/WinInet`,
                "Krnl-Fingerprint": generateId(16)
            }
        })
    
        return [ true, content ]
    } catch (err) {
        console.error("fetch error",err)
        if(!err.statusCode) return [ false, "> Unable to fetch url, message: Unable to establish connection." ]
    
        return [ false, `> Unable to fetch url, message: ${err.statusCode}: ${err.response ? err.response.statusMessage : "NO_STATUS_MESSAGE"}` ]
    }
}

const arg = process.argv[2]
;(async () => {
    if(!arg) return;
    // from lune, just print the output
    const [ success, content ] = await request(arg)

    if(!success) console.error("Unable to fetch request.")
    console.log(content)
})();

module.exports = request
