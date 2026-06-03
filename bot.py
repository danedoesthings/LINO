import discord
import io
import os
import base64
import asyncio
import subprocess
import tempfile
import re
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('deobf-bot')

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN not set.")

intents = discord.Intents.default()
intents.message_content = True

class DeobfBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)

    async def on_ready(self):
        log.info(f'Logged in as {self.user}')

    async def on_message(self, message):
        if message.author.bot:
            return

        if not message.content.startswith('.deobf'):
            return

        raw = None
        filename = 'input.lua'

        if message.attachments:
            att = message.attachments[0]
            if not att.filename.endswith(('.lua', '.luau', '.txt')):
                await message.reply('Please attach a .lua, .luau, or .txt file.')
                return
            if att.size > 5 * 1024 * 1024:
                await message.reply('File too large (max 5MB)')
                return
            raw = await att.read()
            filename = att.filename
        else:
            content = message.content
            cmd_end = content.lower().find('deobf')
            if cmd_end != -1:
                content = content[cmd_end + len('deobf'):].strip()
            code = self.extract_code(content)
            if not code:
                await message.reply('Attach a .lua file or paste code in a codeblock.')
                return
            raw = code.encode('utf-8')

        log.info(f"Deobf request from {message.author} ({filename}, {len(raw)} bytes)")

        msg = await message.reply('Deobfuscating...')
        result = await asyncio.to_thread(self.run_deobf, raw)

        try:
            await msg.delete()
        except:
            pass

        if result:
            await message.reply(file=discord.File(io.BytesIO(result.encode()), filename=f'deobfuscated_{filename}'))
        else:
            await message.reply('Deobfuscation failed.')

    def extract_code(self, content):
        m = re.search(r'```(?:lua|luau|txt)?\s*\n?(.*?)```', content, re.DOTALL)
        if m:
            return m.group(1).strip()
        stripped = content.strip()
        return stripped if stripped else None

    def run_deobf(self, source_bytes):
        with tempfile.NamedTemporaryFile(suffix='.lua', delete=False) as f:
            f.write(source_bytes)
            input_path = f.name

        with tempfile.NamedTemporaryFile(suffix='.lua', delete=False) as f:
            output_path = f.name

        try:
            env = os.environ.copy()
            env['LUNE_PATH'] = '/usr/local/bin/lune'

            result = subprocess.run(
                ['lune', 'run', 'httplog2.lua', input_path, '0', output_path],
                capture_output=True,
                text=True,
                timeout=180,
                env=env
            )

            if result.returncode != 0:
                log.error(f"Lune error: {result.stderr[:500]}")
                return None

            if os.path.exists(output_path):
                with open(output_path, 'r', encoding='utf-8', errors='replace') as out:
                    data = out.read().strip()
                if data and not data.startswith('-- [ERROR]'):
                    return data
            return None
        except subprocess.TimeoutExpired:
            log.error("Timeout during deobfuscation")
            return None
        except Exception as e:
            log.error(f"Deobf error: {e}")
            return None
        finally:
            try: os.unlink(input_path)
            except: pass
            try: os.unlink(output_path)
            except: pass

bot = DeobfBot()
bot.run(TOKEN)
