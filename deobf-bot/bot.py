import discord
import io
import os
import re
import logging
import httpx
import base64
import datetime
import asyncio
import json
from discord.ext import commands

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
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

SUCCESS_METHODS = (
    'lua_harness', 'print_capture', 'wearedevs_string_substitution',
    'wearedevs_vm_lifted', 'state_machine_devirt', 'recursive_unveil',
    'prometheus_vm', 'wearedevs_decode'
)

async def call_api(source_b64, sync=False):
    async with httpx.AsyncClient(timeout=300) as client:
        if sync:
            response = await client.post(f'{API_URL}/deobf/sync', json={'source_b64': source_b64})
            response.raise_for_status()
            return response.json()
        
        response = await client.post(f'{API_URL}/deobf', json={'source_b64': source_b64})
        response.raise_for_status()
        data = response.json()
        
        job_id = data.get('job_id', '').strip()
        if not job_id:
            return data
        
        for attempt in range(180):
            await asyncio.sleep(1)
            try:
                poll = await client.get(f'{API_URL}/deobf/{job_id}')
                if poll.status_code == 404:
                    return {'error': f'Job {job_id} not found. The API may have restarted.'}
                poll.raise_for_status()
                poll_data = poll.json()
                
                if poll_data.get('status') != 'processing':
                    return poll_data
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    return {'error': f'Job {job_id} expired or not found'}
                raise
        
        return {'error': 'Deobfuscation timed out after 180 seconds'}

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

def _sanitize_diag(text):
    return ''.join(c for c in text if c.isprintable() or c in '\n\t')

async def run_deobf(raw_bytes, filename):
    if len(raw_bytes) > MAX_BYTES:
        return {
            'files': [],
            'full_diag': None,
            'embed': discord.Embed(
                title='Error',
                description=f'Input exceeds 5 MB limit ({len(raw_bytes)} bytes)',
                color=0xe74c3c
            ),
        }
    
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api(source_b64, sync=False)
    except httpx.TimeoutException:
        return {
            'embed': discord.Embed(
                title='API Timeout',
                description='Deobfuscation API did not respond within 300 seconds',
                color=0xe74c3c
            ),
            'files': [],
            'full_diag': None,
        }
    except httpx.ConnectError:
        return {
            'files': [],
            'full_diag': None,
            'embed': discord.Embed(
                title='API Unreachable',
                description=f'Cannot connect to {API_URL}. Is the API running?',
                color=0xe74c3c
            ),
        }
    except Exception as e:
        log.error(f"API call failed: {e}")
        return {
            'files': [],
            'full_diag': None,
            'embed': discord.Embed(
                title='API Error',
                description=_truncate(str(e), 1800),
                color=0xe74c3c
            ),
        }
    
    if 'error' in data:
        tb = data.get('traceback', '')
        desc = data['error'][:1500]
        if tb:
            desc += f'\n```\n{_truncate(tb, 800)}\n```'
        return {
            'embed': discord.Embed(
                title='Deobfuscation Failed',
                description=desc,
                color=0xe74c3c
            ),
            'files': [],
            'full_diag': _sanitize_diag(data.get('diagnostic', '')),
        }
    
    result = data.get('result', '')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    trace = data.get('trace', [])
    
    if detected in SUCCESS_METHODS:
        title, color = 'Deobfuscation Complete', 0x2ecc71
    elif detected == 'bytecode':
        title, color = 'Bytecode Extracted', 0xe67e22
    else:
        title, color = 'Deobfuscation Partial', 0xf1c40f
    
    em = discord.Embed(
        title=title,
        color=color,
        timestamp=datetime.datetime.utcnow()
    )
    em.add_field(name='Method', value=f'`{detected}`', inline=True)
    em.add_field(name='Input', value=filename, inline=True)
    em.add_field(name='Result Size', value=f'{len(result)} chars' if result else 'empty', inline=True)
    
    if diagnostic:
        clean = _sanitize_diag(diagnostic)
        short_diag = clean[:900] + ('...' if len(clean) > 900 else '')
        em.add_field(name='Diagnostic', value=f'```\n{short_diag}\n```', inline=False)
    
    if trace:
        stages = [t.get('stage', '?') for t in trace[:10]]
        stage_text = ' -> '.join(stages)
        em.add_field(name='Pipeline', value=_truncate(stage_text, 1000), inline=False)
    
    em.set_footer(text=f'{API_URL} | {datetime.datetime.utcnow().strftime("%H:%M:%S")} UTC')
    
    files = []
    if result and detected != 'bytecode':
        files.append(discord.File(
            fp=io.BytesIO(result.encode('utf-8', errors='replace')),
            filename=f'deobfuscated_{filename}'
        ))
    elif detected == 'bytecode' and result:
        try:
            raw_out = base64.b64decode(result)
            files.append(discord.File(
                fp=io.BytesIO(raw_out),
                filename=f'extracted_{filename}.luac'
            ))
        except:
            files.append(discord.File(
                fp=io.BytesIO(result.encode('utf-8', errors='replace')),
                filename=f'extracted_{filename}.txt'
            ))
    
    full_diag = diagnostic if len(diagnostic) > 900 else None
    return {'embed': em, 'files': files, 'full_diag': full_diag}

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
    
    msg = await ctx.send(embed=discord.Embed(
        title='Deobfuscating...',
        description=f'Processing {filename} ({len(raw)} bytes)',
        color=0x3498db
    ))
    
    res = await run_deobf(raw, filename)
    last_results[ctx.channel.id] = res
    
    try:
        await msg.delete()
    except (discord.NotFound, discord.Forbidden):
        pass
    
    await ctx.send(embed=res['embed'], files=res.get('files', []))
    
    if res.get('full_diag'):
        await ctx.send('Diagnostic was truncated. Use `=fulldiag` to get the full diagnostic as a file.')

@bot.command(name='fulldiag')
async def prefix_fulldiag(ctx):
    res = last_results.get(ctx.channel.id)
    if not res or not res.get('full_diag'):
        return await ctx.send('No truncated diagnostic available. Run `=deobf` first.')
    
    diag_bytes = res['full_diag'].encode('utf-8', errors='replace')
    file = discord.File(fp=io.BytesIO(diag_bytes), filename='full_diagnostic.txt')
    await ctx.send('Full diagnostic:', file=file)

@bot.command(name='ping')
async def prefix_ping(ctx):
    await ctx.send(f'Pong! Latency: {round(bot.latency * 1000)}ms')

@prefix_deobf.error
async def deobf_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f'Cooldown active. Try again in {error.retry_after:.0f}s')
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send('Missing required argument. Usage: `=deobf <file>` or paste code.')
    elif isinstance(error, commands.CommandInvokeError):
        log.error(f"Command invoke error: {error.original}")
        await ctx.send(f'An internal error occurred. Check the logs.')
    else:
        log.error(f"Unhandled command error: {error}")

@tree.command(name='deobf', description='Deobfuscate a Lua file')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        return await interaction.response.send_message(
            'Please attach a `.lua`, `.luau`, or `.txt` file.',
            ephemeral=True
        )
    
    if file.size > MAX_BYTES:
        return await interaction.response.send_message(
            f'File too large ({file.size} bytes, max {MAX_BYTES})',
            ephemeral=True
        )
    
    await interaction.response.defer(thinking=True)
    
    raw = await file.read()
    log.info(f"Slash deobf from {interaction.user} ({file.filename}, {len(raw)} bytes)")
    
    res = await run_deobf(raw, file.filename)
    
    await interaction.followup.send(embed=res['embed'], files=res.get('files', []))
    
    if res.get('full_diag'):
        diag_bytes = res['full_diag'].encode('utf-8', errors='replace')
        diag_file = discord.File(fp=io.BytesIO(diag_bytes), filename='full_diagnostic.txt')
        await interaction.followup.send('Diagnostic was truncated. Full diagnostic:', file=diag_file)

@slash_deobf.error
async def slash_deobf_error(interaction: discord.Interaction, error):
    log.error(f"Slash command error: {error}")
    try:
        await interaction.followup.send(f'An error occurred: {str(error)[:1000]}', ephemeral=True)
    except Exception:
        pass

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
