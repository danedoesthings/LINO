import discord
import io
import os
import base64
import asyncio
import subprocess
import tempfile

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN not set.")

intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)

def run_deobf(source_bytes):
    with tempfile.NamedTemporaryFile(suffix='.lua', delete=False) as f:
        f.write(source_bytes)
        input_path = f.name
    
    with tempfile.NamedTemporaryFile(suffix='.lua', delete=False) as f:
        output_path = f.name
    
    try:
        env = os.environ.copy()
        env['LUNE_PATH'] = os.path.dirname(os.path.abspath(__file__))
        result = subprocess.run(
            ['lune', 'run', 'httplog2.lua', input_path, '0', output_path],
            capture_output=True, text=True, timeout=120, env=env
        )
        if result.returncode == 0 and os.path.exists(output_path):
            with open(output_path, 'r', encoding='utf-8', errors='replace') as out:
                return out.read()
        return None
    finally:
        try: os.unlink(input_path)
        except: pass
        try: os.unlink(output_path)
        except: pass

@bot.event
async def on_ready():
    print(f'Ready: {bot.user}')

@bot.event
async def on_message(msg):
    if msg.author.bot:
        return
    if msg.content.startswith('.deobf'):
        if msg.attachments:
            att = msg.attachments[0]
            if att.filename.endswith('.lua'):
                raw = await att.read()
                await msg.channel.typing()
                result = await asyncio.to_thread(run_deobf, raw)
                if result:
                    await msg.reply(file=discord.File(io.BytesIO(result.encode()), filename='deobfuscated.lua'))
                else:
                    await msg.reply('Deobfuscation failed')
        else:
            await msg.reply('Attach a .lua file')

if __name__ == '__main__':
    bot.run(TOKEN)
