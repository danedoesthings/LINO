import os, re, time, uuid, threading, json, traceback, subprocess, tempfile, shutil, signal
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from string_decoder import StringTableDecoder
from prometheus_decoder import PrometheusDecoder
from anti_tamper import remove_anti_tamper
from var_renamer import VarRenamer
from beautifier import beautify
from env_logger import JobLogger

JOB_STORAGE_DIR = '/data'
JOB_STORAGE_FILE = os.path.join(JOB_STORAGE_DIR, 'deobf_jobs.json')
os.makedirs(JOB_STORAGE_DIR, exist_ok=True)

VM_PATTERNS = [
    r'while\s+\w+\s+do\s+if\s+\w+\s*[<>=]+\s*-?\d+\s+then',
    r'while\s+\w+\s+do\s+if\s+\w+\s*[<>=]',
    r'handlers\s*\[',
    r'instrTbl\s*\[',
    r'vmStack\s*\[',
    r'allocSlot\s*\(\s*\)',
    r'funcWrap\s*\(\s*',
    r'callEnv\w\s*\[',
    r'return\s*\(function\s*\(',
    r'ipairs\s*\(\s*\{\s*\{',
]

def _count_vm_indicators(source: str) -> int:
    if not source:
        return 0
    count = sum(1 for pat in VM_PATTERNS if re.search(pat, source))
    single_letter_vars = len(re.findall(r'\b[a-z]\s*=\s*', source))
    nested_ifs = len(re.findall(r'\bif\b.*\bif\b', source))
    if single_letter_vars > 20 and nested_ifs > 5:
        count += 2
    if source.count('\n') > 500 and re.search(r'\bfunction\b', source):
        count += 1
    return count

def _run_lua_harness(source: str, timeout: int = 30) -> Optional[str]:
    lua_bin = shutil.which('lua5.1') or '/usr/bin/lua5.1'
    if not os.path.isfile(lua_bin):
        return None
    tmpdir = tempfile.mkdtemp()
    try:
        input_path = os.path.join(tmpdir, 'input.lua')
        output_path = os.path.join(tmpdir, 'captured.lua')
        escaped_source = source.replace('\\', '\\\\').replace("'", "\\'")
        harness_code = f'''
local capture = {{}}
local function _c(s)
    if type(s) == "string" and #s > 0 then
        capture[#capture + 1] = s
    end
    return s
end
local _old_loadstring = loadstring or load
loadstring = function(src, name)
    _c(src)
    _c("[PAYLOAD:" .. #src .. "]")
    return _old_loadstring and _old_loadstring(src, name) or function() end
end
load = loadstring
local _old_print = print
print = function(...)
    local args = {{}}
    for i = 1, select("#", ...) do
        args[i] = tostring(select(i, ...))
    end
    _c(table.concat(args, "\\t"))
    return _old_print(...)
end
debug.sethook = function() end
local fn, err = loadstring([[{escaped_source}]])
if fn then
    local ok, result = pcall(fn)
    if ok and type(result) == "function" then
        pcall(result)
    end
end
local f = io.open("{output_path.replace(chr(92), '/')}", "w")
if f then
    f:write(table.concat(capture, "\\n"))
    f:close()
end
'''
        harness_path = os.path.join(tmpdir, 'harness.lua')
        with open(harness_path, 'w', encoding='utf-8') as f:
            f.write(harness_code)
        proc = subprocess.Popen(
            [lua_bin, harness_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True
        )
        try:
            proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except:
                pass
        if os.path.exists(output_path):
            with open(output_path, 'r', encoding='utf-8', errors='replace') as f:
                captured = f.read().strip()
                if captured and len(captured) > 5:
                    return captured
        return None
    except Exception:
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

@dataclass
class DiagnosticEvent:
    stage: str
    success: bool
    message: str
    timestamp: float = field(default_factory=time.time)

class Unveiler:
    def __init__(self) -> None:
        pass

    def unveil(self, source: str, trace: list = None, depth: int = 0) -> Tuple[str, str, str, list]:
        if trace is None:
            trace = []
        def log(stage, success, message):
            trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})

        if depth > 5:
            log('max_depth', False, 'recursion limit reached')
            return source, 'max_depth', 'Recursion limit reached', trace

        source = remove_anti_tamper(source)
        log('anti_tamper', True, 'anti-tamper block removed')

        decoder = StringTableDecoder(source)
        if not decoder.ok:
            log('decode', False, decoder.diagnostics.get('error', 'decode failed'))
            return '', 'unable', 'String decode failed', trace
        log('decode', True, f'decoded {len(decoder.strings)} strings')

        try:
            prom_decoder = PrometheusDecoder(source, decoder)
            result = prom_decoder.decode()
            if result and len(result) > 10:
                vm_count = _count_vm_indicators(result)
                log('prometheus_decode', True, f'produced {len(result)} chars, VM indicators: {vm_count}')
                if vm_count < 2:
                    renamer = VarRenamer()
                    result = renamer.rename(result)
                    result = beautify(result)
                    return result, 'prometheus_decode', 'Static decode complete', trace

                log('dynamic', True, f'VM detected ({vm_count} indicators), attempting dynamic execution')
                harness_output = _run_lua_harness(result, timeout=30)
                if harness_output:
                    payloads = re.findall(r'\[PAYLOAD:(\d+)\]', harness_output)
                    if payloads:
                        lines = harness_output.split('\n')
                        for i, line in enumerate(lines):
                            if line.startswith('[PAYLOAD:') and i + 1 < len(lines):
                                payload = lines[i + 1].strip()
                                if len(payload) > 50 and not re.search(r'while\s+\w+\s+do', payload):
                                    inner_result, inner_method, inner_diag, _ = self.unveil(payload, trace, depth + 1)
                                    if inner_result and len(inner_result) > 10:
                                        return inner_result, f'dynamic+{inner_method}', inner_diag, trace
        except Exception as e:
            log('prometheus_decode', False, f'decode failed: {str(e)[:100]}')

        try:
            lines = []
            for i, s in enumerate(decoder.strings):
                if s:
                    lines.append(f'-- [{i+1}] {json.dumps(s)}')
            lines.append('')
            lines.append(f'-- Detected getter offset: {decoder.offset}')
            lines.append(f'-- Alphabet: {decoder.alphabet or "not found"}')
            lines.append('-- Could not fully reconstruct original source')
            return '\n'.join(lines), 'string_table', 'Decoded string table', trace
        except:
            return '', 'unable', 'All decode stages failed', trace

class DeobfEngine:
    def __init__(self) -> None:
        self.var_renamer = VarRenamer()

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            'anti_tamper': True,
            'prometheus_decode': True,
            'dynamic_harness': True,
            'string_table_dump': True,
            'var_renamer': True,
            'beautifier': True,
        }

    def process(self, source: str, logger: Optional[JobLogger] = None) -> Tuple[str, str, str, list]:
        unveiler = Unveiler()
        result, method, diagnostic, trace = unveiler.unveil(source)
        if logger:
            for entry in trace:
                logger.add_trace(entry['stage'], entry['success'], entry['message'])
            logger.finish(result, method, diagnostic)
        return result, method, diagnostic, trace

job_store: Dict[str, Any] = {}
job_lock = threading.Lock()
_jobs_loaded = False

def _save_jobs() -> None:
    try:
        with job_lock:
            completed = {k: v for k, v in job_store.items() if v.get('status') != 'processing'}
            with open(JOB_STORAGE_FILE, 'w') as f:
                json.dump(completed, f)
    except Exception:
        pass

def _load_jobs() -> None:
    global _jobs_loaded
    if _jobs_loaded:
        return
    try:
        if os.path.exists(JOB_STORAGE_FILE):
            with open(JOB_STORAGE_FILE) as f:
                with job_lock:
                    job_store.update(json.load(f))
        _jobs_loaded = True
    except Exception:
        pass

def _cleanup_old_jobs() -> None:
    while True:
        try:
            time.sleep(3600)
            now = time.time()
            with job_lock:
                old = [k for k, v in job_store.items() if now - v.get('created', 0) > 86400]
                for k in old:
                    del job_store[k]
                _save_jobs()
        except Exception:
            pass

_load_jobs()
_cleanup_thread = threading.Thread(target=_cleanup_old_jobs, daemon=True)
_cleanup_thread.start()

def _run_job(job_id: str, source: str) -> None:
    engine = DeobfEngine()
    logger = JobLogger()
    logger.start(job_id, engine.get_capabilities())
    try:
        result, method, diagnostic, trace = engine.process(source, logger)
        with job_lock:
            job_store[job_id] = {
                'status': 'complete',
                'result': result,
                'detected': method,
                'diagnostic': diagnostic,
                'trace': trace,
                'result_length': len(result) if result else 0,
                'created': job_store.get(job_id, {}).get('created', time.time()),
                'log_json': logger.to_json(),
            }
        _save_jobs()
    except Exception as e:
        logger.add_error(str(e), e)
        logger.finish()
        with job_lock:
            job_store[job_id] = {
                'status': 'error',
                'error': str(e),
                'traceback': traceback.format_exc()[:4000],
                'created': job_store.get(job_id, {}).get('created', time.time()),
                'log_json': logger.to_json(),
            }
        _save_jobs()

def submit_job(source: str) -> str:
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}
    threading.Thread(target=_run_job, args=(job_id, source), daemon=True).start()
    return job_id

def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with job_lock:
        return job_store.get(job_id)
