import discord, io, os, re, logging, httpx, base64, asyncio
from discord.ext import commands

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('deobf-bot')

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
API_URL = os.environ.get('DEOBF_API_URL', 'http://localhost:5000')

if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN not set.")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='=', intents=intents, help_command=None)
tree = bot.tree

ALLOWED_EXTENSIONS = ('.lua', '.txt', '.luau')
MAX_BYTES = 5 * 1024 * 1024

SUCCESS_METHODS = (
    'unluac', 'sandbox_capture', 'sandbox_unluac', 'sandbox_scan',
    'sandbox_string', 'lune_capture', 'lune_unluac', 'rapid_decode_unluac',
    'string_decode', 'string_decode_unluac', 'deep_scan_unluac',
    'WeAreDevsLifter_unluac', 'MoonSecLifter_unluac', 'IronBrewLifter_unluac',
    'PSULifter_unluac', 'XORStringDecoder_unluac', 'NumberArrayDecoder_unluac',
    'StandardBase64Decoder_unluac', 'WeAreDevsLifter_source', 'MoonSecLifter_source',
    'IronBrewLifter_source', 'recursive_unluac', 'recursive_sandbox_capture',
    'recursive_lune_capture', 'recursive_sandbox_unluac',
)

async def call_api(source_b64):
    async with httpx.AsyncClient(timeout=180) as c:
        r = await c.post(f'{API_URL}/deobf', json={'source_b64': source_b64})
        r.raise_for_status()
        return r.json()

def _extract_inline_code(content):
    m = re.search(r'```(?:lua|luau|txt)?\s*\n?(.*?)```', content, re.DOTALL)
    if m:
        return m.group(1).strip()
    stripped = content.strip()
    return stripped or None

async def run_deobf(raw_bytes, filename):
    if len(raw_bytes) > MAX_BYTES:
        return {'embed': discord.Embed(title='Error', description='Input exceeds 5 MB limit', color=0xe74c3c), 'files': []}
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api(source_b64)
    except Exception as e:
        log.error(f"API call failed: {e}")
        return {'embed': discord.Embed(title='API Error', description=str(e)[:1800], color=0xe74c3c), 'files': []}
    if 'error' in data:
        return {'embed': discord.Embed(title='Deobfuscation Failed', description=data['error'][:1800], color=0xe74c3c), 'files': []}
    result = data.get('result', '')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    trace = data.get('trace', [])
    if detected in SUCCESS_METHODS:
        title, color = 'Deobfuscation Complete', 0x2ecc71
    elif detected == 'bytecode':
        title, color = 'Bytecode Extracted', 0xe67e22
    else:
        title, color = 'Deobfuscation Failed', 0xe74c3c
    em = discord.Embed(title=title, color=color)
    em.add_field(name='Method', value=f'`{detected}`', inline=True)
    em.add_field(name='Input', value=filename, inline=True)
    if diagnostic:
        em.add_field(name='Diagnostic', value=diagnostic[:1000], inline=False)
    if trace:
        stages = [t.get('stage', '?') for t in trace[:8]]
        em.add_field(name='Pipeline', value=' -> '.join(stages)[:1000], inline=False)
    files = []
    if result and detected != 'bytecode':
        files.append(discord.File(fp=io.BytesIO(result.encode('utf-8', errors='replace')), filename=f'deobf_{filename}'))
    elif detected == 'bytecode' and result:
        raw_out = base64.b64decode(result)
        files.append(discord.File(fp=io.BytesIO(raw_out), filename=f'extracted_{filename}.luac'))
    return {'embed': em, 'files': files}

@bot.command(name='deobf')
@commands.cooldown(1, 30, commands.BucketType.user)
async def prefix_deobf(ctx):
    raw, filename = None, 'input.lua'
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.lower().endswith(ALLOWED_EXTENSIONS):
            return await ctx.send('Please attach a `.lua`, `.luau`, or `.txt` file.')
        if att.size > MAX_BYTES:
            return await ctx.send('File exceeds 5 MB limit.')
        raw, filename = await att.read(), att.filename
    else:
        body = ctx.message.content
        cmd_end = body.lower().find('deobf')
        if cmd_end != -1:
            body = body[cmd_end + len('deobf'):].strip()
        code = _extract_inline_code(body)
        if not code:
            return await ctx.send('Attach a `.lua` file or paste code after `=deobf`.')
        raw = code.encode('utf-8')
    log.info(f"Deobf request from {ctx.author} ({filename}, {len(raw)} bytes)")
    msg = await ctx.send(embed=discord.Embed(title='Deobfuscating...', description='Running multi-stage pipeline. This may take up to 120 s.', color=0x3498db))
    res = await run_deobf(raw, filename)
    try:
        await msg.delete()
    except discord.NotFound:
        pass
    await ctx.send(embed=res['embed'], files=res.get('files', []))

@prefix_deobf.error
async def deobf_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f'Cooldown - try again in {error.retry_after:.0f}s.')

@tree.command(name='deobf', description='Deobfuscate a Lua file')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        return await interaction.response.send_message('Please attach a `.lua`, `.luau`, or `.txt` file.', ephemeral=True)
    if file.size > MAX_BYTES:
        return await interaction.response.send_message('File exceeds 5 MB limit.', ephemeral=True)
    await interaction.response.defer(thinking=True)
    raw = await file.read()
    log.info(f"Slash deobf from {interaction.user} ({file.filename}, {len(raw)} bytes)")
    res = await run_deobf(raw, file.filename)
    await interaction.followup.send(embed=res['embed'], files=res.get('files', []))

@bot.event
async def on_ready():
    await tree.sync()
    log.info(f'Ready: {bot.user} | API: {API_URL}')

if __name__ == '__main__':
    bot.run(TOKEN)
