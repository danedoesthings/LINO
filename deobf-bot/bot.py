import discord
import io
import os
import re
import logging
import httpx
import base64
import datetime
import asyncio
from discord.ext import commands
from discord import app_commands

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('deobf-bot')

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
API_URL = os.environ.get('DEOBF_API_URL', 'http://localhost:5000').strip().rstrip('/')
if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN not set.")

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='=', intents=intents, help_command=None)
tree = bot.tree

ALLOWED_EXTENSIONS = ('.lua', '.txt', '.luau')
MAX_BYTES = 5 * 1024 * 1024
SUCCESS_METHODS = ('prometheus_decode', 'vm_devirtualized', 'dynamic+prometheus_decode')

async def call_api_direct(source_b64):
    async with httpx.AsyncClient(timeout=180) as client:
        response = await client.post(f'{API_URL}/deobf/direct', json={'source_b64': source_b64})
        response.raise_for_status()
        return response.json()

def _extract_inline_code(content):
    m = re.search(r'```(?:lua|luau|txt)?\s*\n?(.*?)```', content, re.DOTALL)
    if m:
        return m.group(1).strip()
    stripped = content.strip()
    return stripped or None

def _truncate(text, max_len):
    if len(text) <= max_len:
        return text
    return text[:max_len-3] + '...'

async def run_deobf(raw_bytes, filename):
    if len(raw_bytes) > MAX_BYTES:
        return {'files': [], 'embed': discord.Embed(title='Error', description=f'Input exceeds 5 MB limit ({len(raw_bytes)} bytes)', color=0xe74c3c)}
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api_direct(source_b64)
    except httpx.TimeoutException:
        return {'embed': discord.Embed(title='API Timeout', description='API did not respond within 180 seconds', color=0xe74c3c), 'files': []}
    except httpx.ConnectError:
        return {'embed': discord.Embed(title='API Unreachable', description=f'Cannot connect to {API_URL}', color=0xe74c3c), 'files': []}
    except httpx.HTTPStatusError as e:
        error_body = e.response.text[:1500] if e.response.text else str(e)
        return {'embed': discord.Embed(title=f'API Error {e.response.status_code}', description=error_body, color=0xe74c3c), 'files': []}
    except Exception as e:
        log.error(f"API call failed: {e}")
        return {'embed': discord.Embed(title='API Error', description=_truncate(str(e), 1800), color=0xe74c3c), 'files': []}

    # Handle non-JSON or malformed responses
    if not isinstance(data, dict):
        return {'embed': discord.Embed(title='API Error', description='API returned malformed response', color=0xe74c3c), 'files': []}
    
    if data.get('status') != 'complete':
        error_msg = data.get('error', 'Unknown error') if isinstance(data, dict) else 'Invalid API response'
        return {'embed': discord.Embed(title='Deobfuscation Failed', description=error_msg[:1500], color=0xe74c3c), 'files': []}
    
    result = data.get('result', '')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    trace = data.get('trace', [])
    
    if detected in SUCCESS_METHODS:
        title, color = 'Deobfuscation Complete', 0x2ecc71
    else:
        title, color = 'Partial Result — String Table Dump', 0xf1c40f
    
    em = discord.Embed(title=title, color=color, timestamp=datetime.datetime.utcnow())
    em.add_field(name='Method', value=f'`{detected}`', inline=True)
    em.add_field(name='Input', value=filename, inline=True)
    em.add_field(name='Result Size', value=f'{len(result)} chars' if result else 'empty', inline=True)
    if diagnostic:
        em.add_field(name='Diagnostic', value=f'```\n{diagnostic[:900]}\n```', inline=False)
    if trace:
        stages = [t.get('stage', '?') for t in trace[:10]]
        em.add_field(name='Pipeline', value=_truncate(' -> '.join(stages), 1000), inline=False)
    em.set_footer(text=f'{API_URL} | {datetime.datetime.utcnow().strftime("%H:%M:%S")} UTC')
    
    files = []
    if result:
        files.append(discord.File(fp=io.BytesIO(result.encode('utf-8', errors='replace')), filename=f'deobfuscated_{filename}'))
    return {'embed': em, 'files': files}

last_results = {}

@bot.command(name='deobf')
@commands.cooldown(1, 30, commands.BucketType.user)
async def prefix_deobf(ctx):
    raw, filename = None, 'input.lua'
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if not att.filename.lower().endswith(ALLOWED_EXTENSIONS):
            return await ctx.send('Please attach a `.lua`, `.luau`, or `.txt` file.')
        if att.size > MAX_BYTES:
            return await ctx.send(f'File too large ({att.size} bytes, max {MAX_BYTES})')
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
    msg = await ctx.send(embed=discord.Embed(title='Deobfuscating...', description=f'Processing {filename} ({len(raw)} bytes)', color=0x3498db))
    res = await run_deobf(raw, filename)
    last_results[ctx.channel.id] = res
    if len(last_results) > 100:
        oldest = next(iter(last_results))
        del last_results[oldest]
    try:
        await msg.delete()
    except (discord.NotFound, discord.Forbidden):
        pass
    await ctx.send(embed=res['embed'], files=res.get('files', []))

@bot.command(name='ping')
async def prefix_ping(ctx):
    await ctx.send(f'Pong! Latency: {round(bot.latency * 1000)}ms')

@prefix_deobf.error
async def deobf_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f'Cooldown active. Try again in {error.retry_after:.0f}s')
    else:
        log.error(f"Command error: {error}")
        await ctx.send(f'An error occurred: {str(error)[:500]}')

@tree.command(name='deobf', description='Deobfuscate a Prometheus/WeAreDevs Lua script')
@app_commands.describe(file='The .lua, .luau, or .txt file to deobfuscate')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)
    
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        await interaction.followup.send(f'Please upload a {", ".join(ALLOWED_EXTENSIONS)} file')
        return
    
    if file.size > MAX_BYTES:
        await interaction.followup.send(f'File too large ({file.size} bytes, max {MAX_BYTES})')
        return
    
    raw = await file.read()
    log.info(f"Slash deobf from {interaction.user} ({file.filename}, {len(raw)} bytes)")
    res = await run_deobf(raw, file.filename)
    await interaction.followup.send(embed=res['embed'], files=res.get('files', []))

@bot.event
async def on_ready():
    try:
        await tree.sync()
        log.info('Synced commands globally')
    except Exception as e:
        log.error(f"Failed to sync commands: {e}")
    log.info(f'Ready: {bot.user} | API: {API_URL}')

if __name__ == '__main__':
    bot.run(TOKEN)
