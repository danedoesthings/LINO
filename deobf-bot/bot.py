import discord
import io
import base64
import httpx
from discord.ext import commands

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
API_URL = os.environ.get('API_URL', 'http://localhost:5000')

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.command(name='deobf')
async def deobf(ctx):
    if not ctx.message.attachments:
        await ctx.send("Please attach a .lua file")
        return
    
    att = ctx.message.attachments[0]
    if not att.filename.endswith('.lua'):
        await ctx.send("Please attach a .lua file")
        return
    
    await ctx.send("Deobfuscating...")
    
    raw = await att.read()
    b64 = base64.b64encode(raw).decode()
    
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(f'{API_URL}/deobf/direct', json={'source_b64': b64})
        data = resp.json()
    
    if data.get('status') != 'complete':
        await ctx.send(f"Failed: {data.get('error', 'Unknown error')}")
        return
    
    result = data.get('result', '')
    if not result:
        await ctx.send("No output produced")
        return
    
    file = discord.File(io.BytesIO(result.encode()), filename='deobfuscated.lua')
    await ctx.send(file=file)

@bot.event
async def on_ready():
    print(f'Bot ready: {bot.user}')

if __name__ == '__main__':
    bot.run(TOKEN)
