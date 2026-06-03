import discord
import io
import os
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

def decode_wearedevs(code: bytes) -> bytes:
    """Decode WeAreDevs v1 decimal escape sequences before deobfuscation."""
    if b'wearedevs.net/obfuscator' not in code:
        return code
    log.info("Detected WeAreDevs v1 - decoding decimal escapes")
    # Correct regex: match backslash followed by exactly 3 digits
    return re.sub(rb'\\(\d{3})', lambda m: bytes([int(m.group(1))]), code)


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

        # ---- Pre-process: decode WeAreDevs v1 decimal escapes ----
        raw = decode_wearedevs(raw)

        log.info(f"Deobf request from {message.author} ({filename}, {len(raw)} bytes)")
        msg = await message.reply('Deobfuscating...')

        result = await asyncio.to_thread(self.run_deobf, raw, filename)

        try:
            await msg.delete()
        except:
            pass

        if result:
            await message.reply(
                file=discord.File(
                    io.BytesIO(result.encode()),
                    filename=f'deobfuscated_{filename}'
                )
            )
        else:
            await message.reply('Deobfuscation failed.')

    def extract_code(self, content):
        m = re.search(r'```(?:lua|luau|txt)?\s*\n?(.*?)```', content, re.DOTALL)
        if m:
            return m.group(1).strip()
        stripped = content.strip()
        return stripped if stripped else None

    def run_deobf(self, source_bytes, original_filename='input.lua'):
        # Write input file as plain filename in current working directory
        input_name = f'input_{original_filename}'
        with open(input_name, 'wb') as f:
            f.write(source_bytes)

        output_name = f'output_{original_filename}'

        try:
            env = os.environ.copy()
            env['LUNE_PATH'] = '/usr/local/bin/lune'

            result = subprocess.run(
                ['lune', 'run', 'httplog2.lua', input_name, '0', output_name],
                capture_output=True,
                text=True,
                timeout=180,
                env=env
            )

            if result.returncode != 0:
                log.error(f"Lune error: {result.stderr[:500]}")
                return None

            # httplog2.lua now writes to output_name in CWD (we use commercial mode)
            if os.path.exists(output_name):
                with open(output_name, 'r', encoding='utf-8', errors='replace') as out:
                    data = out.read().strip()
                    if data and not data.startswith('-- [ERROR]'):
                        return data
            # Fallback: check stdout for printed result (httplog2 prints it)
            if result.stdout.strip():
                return result.stdout.strip()

            return None

        except subprocess.TimeoutExpired:
            log.error("Timeout during deobfuscation")
            return None
        except Exception as e:
            log.error(f"Deobf error: {e}")
            return None
        finally:
            try:
                os.remove(input_name)
            except:
                pass
            try:
                os.remove(output_name)
            except:
                pass


bot = DeobfBot()
bot.run(TOKEN)
