import os
import discord
import io
import base64
import httpx
import asyncio
from discord.ext import commands
from discord import app_commands

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
API_URL = os.environ.get('API_URL', 'http://api:5000')

if not TOKEN:
    raise SystemExit("DISCORD_BOT_TOKEN environment variable not set")

ALLOWED_EXTENSIONS = ('.lua', '.txt', '.luau')

intents = discord.Intents.default()
intents.message_content = True

class DeobfBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix='!', intents=intents)
    
    async def setup_hook(self):
        await self.tree.sync()
        print(f"Slash commands synced for {self.user}")

bot = DeobfBot()

@bot.event
async def on_ready():
    print(f'Bot ready: {bot.user} (ID: {bot.user.id})')
    print(f'API URL: {API_URL}')
    print(f'Guilds: {[g.name for g in bot.guilds]}')

@bot.command(name='deobf')
async def prefix_deobf(ctx):
    if not ctx.message.attachments:
        await ctx.send("Please attach a `.lua`, `.luau`, or `.txt` file\nUsage: `!deobf` with an attached file")
        return
    
    att = ctx.message.attachments[0]
    if not att.filename.lower().endswith(ALLOWED_EXTENSIONS):
        await ctx.send(f"Please attach a {', '.join(ALLOWED_EXTENSIONS)} file")
        return
    
    msg = await ctx.send(f"⏳ Deobfuscating `{att.filename}`...")
    
    raw = await att.read()
    b64 = base64.b64encode(raw).decode()
    
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(f'{API_URL}/deobf/direct', json={'source_b64': b64})
            data = resp.json()
    except Exception as e:
        await msg.edit(content=f"❌ API error: {str(e)[:200]}")
        return
    
    if data.get('status') != 'complete':
        await msg.edit(content=f"❌ Failed: {data.get('error', 'Unknown error')}")
        return
    
    result = data.get('result', '')
    if not result:
        await msg.edit(content="❌ No output produced")
        return
    
    out_filename = att.filename.replace('.txt', '.lua').replace('.luau', '.lua')
    if not out_filename.endswith('.lua'):
        out_filename = 'deobfuscated.lua'
    
    file = discord.File(io.BytesIO(result.encode()), filename=out_filename)
    await msg.delete()
    await ctx.send(f"✅ Deobfuscated `{att.filename}` → `{out_filename}`", file=file)

@bot.command(name='ping')
async def prefix_ping(ctx):
    await ctx.send(f'Pong! {round(bot.latency * 1000)}ms')

@bot.tree.command(name='deobf', description='Deobfuscate a Prometheus/WeAreDevs Lua script')
@app_commands.describe(file='The .lua, .luau, or .txt file to deobfuscate')
async def slash_deobf(interaction: discord.Interaction, file: discord.Attachment):
    await interaction.response.defer(thinking=True)
    
    if not file.filename.lower().endswith(ALLOWED_EXTENSIONS):
        await interaction.followup.send(f"Please upload a {', '.join(ALLOWED_EXTENSIONS)} file")
        return
    
    raw = await file.read()
    b64 = base64.b64encode(raw).decode()
    
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(f'{API_URL}/deobf/direct', json={'source_b64': b64})
            data = resp.json()
    except Exception as e:
        await interaction.followup.send(f"❌ API error: {str(e)[:200]}")
        return
    
    if data.get('status') != 'complete':
        await interaction.followup.send(f"❌ Failed: {data.get('error', 'Unknown error')}")
        return
    
    result = data.get('result', '')
    if not result:
        await interaction.followup.send("❌ No output produced")
        return
    
    out_filename = file.filename.replace('.txt', '.lua').replace('.luau', '.lua')
    if not out_filename.endswith('.lua'):
        out_filename = 'deobfuscated.lua'
    
    file_obj = discord.File(io.BytesIO(result.encode()), filename=out_filename)
    await interaction.followup.send(f"✅ Deobfuscated `{file.filename}` → `{out_filename}`", file=file_obj)

async def main():
    async with bot:
        await bot.start(TOKEN)

if __name__ == '__main__':
    asyncio.run(main())
