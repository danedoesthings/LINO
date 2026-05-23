import discord, io, os, re, logging, httpx, base64, datetime
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
    'AdvancedWeAreDevsLifter_unluac', 'AdvancedWeAreDevsLifter_nested_unluac',
    'AdvancedWeAreDevsLifter_source',
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

def _truncate(text, max_len):
    if len(text) <= max_len:
        return text
    return text[:max_len-3] + '...'

async def run_deobf(raw_bytes, filename):
    if len(raw_bytes) > MAX_BYTES:
        return {'embed': discord.Embed(title='Error', description=f'Input exceeds 5 MB limit ({len(raw_bytes)} bytes)', color=0xe74c3c), 'files': []}
    try:
        source_b64 = base64.b64encode(raw_bytes).decode('ascii')
        data = await call_api(source_b64)
    except httpx.TimeoutException:
        return {'embed': discord.Embed(title='API Timeout', description='Deobfuscation API did not respond within 180 seconds', color=0xe74c3c), 'files': []}
    except httpx.ConnectError:
        return {'embed': discord.Embed(title='API Unreachable', description=f'Cannot connect to {API_URL}', color=0xe74c3c), 'files': []}
    except Exception as e:
        log.error(f"API call failed: {e}")
        return {'embed': discord.Embed(title='API Error', description=_truncate(str(e), 1800), color=0xe74c3c), 'files': []}
    if 'error' in data:
        tb = data.get('traceback', '')
        desc = data['error'][:1500]
        if tb:
            desc += f'\n```\n{_truncate(tb, 800)}\n```'
        return {'embed': discord.Embed(title='Deobfuscation Failed', description=desc, color=0xe74c3c), 'files': []}
    result = data.get('result', '')
    detected = data.get('detected', 'unknown')
    diagnostic = data.get('diagnostic', '')
    trace = data.get('trace', [])
    if detected in SUCCESS_METHODS:
        title
