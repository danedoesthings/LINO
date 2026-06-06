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
        await ctx.send("Please attach a .lua file\nUsage: `!deobf` with an attached file")
        return
    
    att = ctx.message.attachments[0]
    if not att.filename.endswith('.lua'):
        await ctx.send("Please attach a .lua file")
        return
    
    msg = await ctx.send("⏳ Deobfuscating...")
    
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
    
    file = discord.File(io.BytesIO(result.encode()), filename='deobfuscated.lua')
    await msg.delete()
    await ctx.send(file=file)

@bot.command(name='ping')
async def prefix_ping(ctx):
    await ctx.send(f'Pong! {round(bot.latency * 1000)}ms')

async def main():
    async with bot:
        await bot.start(TOKEN)

if __name__ == '__main__':
    asyncio.run(main())
