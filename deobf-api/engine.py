import os, re, shutil, time, uuid, threading, json, traceback, subprocess, tempfile, base64, urllib.request
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from string_decoder import StringTableDecoder
from devirtualiser import Devirtualiser, strip_bootstrap
from state_machine_devirt import StateMachineLifter
from vm_devirtualizer import VMDevirtualizer
from instruction_table_dumper import InstructionTableDumper
from loadstring_extractor import LoadstringPayloadExtractor
from prometheus_decoder import PrometheusDecoder
from var_renamer import VarRenamer
from beautifier import beautify
from env_logger import JobLogger
from lua_harness import LuaHarness
from lune_pipeline import run_lune_darklua_pipeline
from constants import looks_like_real_code, is_lua_bytecode, LUA_KEYWORDS, is_probably_text
from instruction_decoder import WeAreDevsVMLifter
try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

JOB_STORAGE_DIR = '/data'
JOB_STORAGE_FILE = os.path.join(JOB_STORAGE_DIR, 'deobf_jobs.json')
os.makedirs(JOB_STORAGE_DIR, exist_ok=True)

@dataclass
class DiagnosticEvent:
    stage: str
    success: bool
    message: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None
    exception_type: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

class Unveiler:
    def __init__(self, harness: LuaHarness) -> None:
        self.harness = harness

    def _is_valid_lua(self, code: str) -> bool:
        sanitized = re.sub(r'[^\x20-\x7E\n\r\t]', '', code)
        if not HAS_LUAPARSER:
            return True
        try:
            lua_ast.parse(sanitized)
            return True
        except Exception:
            return False

    def _score_lua_quality(self, code: str) -> int:
        score = 0
        if not code or len(code) < 10:
            return 0
        if self._is_valid_lua(code):
            score += 50
        score += len(re.findall(r'\bfunction\b', code)) * 10
        score += len(re.findall(r'\blocal\s+\w+\s*=', code)) * 5
        score += len(re.findall(r'\breturn\b', code)) * 8
        score += len(re.findall(r'\bif\b.*\bthen\b', code)) * 8
        score += len(re.findall(r'\bwhile\b.*\bdo\b', code)) * 8
        score += len(re.findall(r'\bfor\b.*\bdo\b', code)) * 8
        score += len(re.findall(r'\bend\b', code)) * 5
        vm_dispatch_count = len(re.findall(r'while\s+\w+\s+do\s+if\s+\w+\s*[<>=]+\s*-?\d+\s+then', code))
        score -= vm_dispatch_count * 20
        score -= len(re.findall(r'vmState\s*=\s*-?\d+', code)) * 20
        score -= len(re.findall(r'GetStr\s*\(', code)) * 30
        score -= len(re.findall(r'EncStr\s*\[', code)) * 15
        return score

    def _is_quality_output(self, code: str) -> bool:
        return self._score_lua_quality(code) >= 20

    def _extract_payload_from_harness_output(self, output: str) -> Optional[str]:
        lines = output.split('\n')
        payloads = []
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith('[Payload:') and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if len(next_line) > 50 and not next_line.startswith('['):
                    payloads.append(next_line)
        if payloads:
            return payloads[-1]
        for line in lines:
            line = line.strip()
            if len(line) > 200 and not line.startswith('[') and not line.startswith('--'):
                if 'function' in line or 'local' in line or 'print' in line or 'return' in line:
                    return line
        return None

    def _calculate_vm_score(self, source: str) -> int:
        score = 0
        indicators = [
            (r'while\s+\w+\s+do\s+if\s+\w+\s*[<>=]+\s*-?\d+\s+then', 20),
            (r'if\s+\w+\s*[<>=]+\s*-?\d+\s+then', 5),
            (r'local\s+function\s+\w+\s*\([^)]*\)\s*return\s+R\s*\[[^\]]*[+\-*/%][^\]]*\d+\]', 15),
            (r'\w+\s*=\s*\{\s*\[?\d+\]?\s*=\s*function', 10),
            (r'for\s+\w+\s*,\s*\w+\s+in\s+ipairs', 15),
            (r'return\s*\(function\s*\(', 15),
            (r'instrTbl', 10),
            (r'callEnvA', 10),
            (r'callEnvB', 10),
            (r'vmStack', 10),
            (r'allocSlot', 10),
            (r'funcWrap', 10),
            (r'local\s+function\s+\w\s*\(\s*\w\s*\)\s*return\s+R\s*\[', 20),
            (r'R\s*\[', 5),
        ]
        for pattern, weight in indicators:
            score += len(re.findall(pattern, source)) * weight
        if score < 10:
            if 'return(function(' in source or 'ipairs({{' in source:
                score = 50
        return score

    def unveil(self, source: str, depth: int = 0, trace: list = None) -> Tuple[str, str, str, list]:
        if trace is None:
            trace = []
        def log(stage, success, message):
            trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})
        if depth > 5:
            log('max_depth', False, 'Recursion limit reached')
            return source, 'max_depth', 'Recursion limit reached', trace

        decoder = StringTableDecoder(source)
        if not decoder.ok:
            log('decode', False, decoder.diagnostics.get('error', 'decode failed'))
            return '', 'unable', 'String decode failed', trace
        log('decode', True, f'decoded {len(decoder.strings)} strings (depth {depth})')

        vm_score = self._calculate_vm_score(source)
        log('vm_detect', True, f'VM score: {vm_score}')

        if vm_score >= 10:
            log('prometheus_decode', True, 'VM detected, attempting Prometheus-aware static decode')
            try:
                prom_decoder = PrometheusDecoder(source, decoder)
                result = prom_decoder.decode()
                if result and len(result) > 10 and self._is_valid_lua(result):
                    renamer = VarRenamer()
                    result = renamer.rename(result)
                    result = beautify(result)
                    log('prometheus_decode', True, f'Prometheus decode produced {len(result)} chars')
                    return result, 'prometheus_decode', 'Prometheus static decode complete', trace
            except Exception as e:
                log('prometheus_decode', False, f'Prometheus decode failed: {str(e)[:100]}')

        if vm_score >= 10:
            log('harness', True, 'VM detected, attempting dynamic harness execution')
            harness_result = self.harness.run(source, timeout=120, decoded_strings=decoder.strings)
            if harness_result and len(harness_result) > 100:
                payload = self._extract_payload_from_harness_output(harness_result)
                if payload:
                    log('harness_success', True, f'inner payload extracted ({len(payload)} bytes)')
                    renamer = VarRenamer()
                    payload = renamer.rename(payload)
                    payload = beautify(payload)
                    return payload, 'dynamic_harness', 'Dynamic harness execution complete', trace
                elif self._is_quality_output(harness_result):
                    log('harness_success', True, f'dynamic harness produced {len(harness_result)} chars')
                    renamer = VarRenamer()
                    harness_result = renamer.rename(harness_result)
                    harness_result = beautify(harness_result)
                    return harness_result, 'dynamic_harness', 'Dynamic harness execution complete', trace

        if vm_score >= 15:
            log('devirtualise', True, 'VM detected, attempting AST-based VM devirtualization')
            try:
                vm_devirt = VMDevirtualizer(source, decoder)
                lifted = vm_devirt.devirtualize()
                if lifted and self._is_valid_lua(lifted):
                    log('devirtualise_success', True, f'VM lifted via AST, {len(vm_devirt.states)} states')
                    renamer = VarRenamer()
                    lifted = renamer.rename(lifted)
                    lifted = beautify(lifted)
                    return lifted, 'vm_devirtualized', 'VM successfully devirtualized via AST analysis', trace
                else:
                    diag_msg = '; '.join(vm_devirt.diagnostics) if vm_devirt.diagnostics else 'returned None/empty'
                    log('devirtualise', False, f'VM devirtualizer: {diag_msg}')
            except Exception as e:
                log('devirtualise', False, f'VM devirtualizer exception: {str(e)[:200]}')

        if vm_score >= 10:
            log('devirtualise', True, 'attempting instruction-level VM lifting')
            vm_lifter = WeAreDevsVMLifter(decoder.strings, offset=decoder.offset)
            lifted = vm_lifter.lift(source)
            if lifted and self._is_valid_lua(lifted):
                renamer = VarRenamer()
                lifted = renamer.rename(lifted)
                lifted = beautify(lifted)
                log('devirtualise_success', True, 'VM lifted via instruction decoder')
                return lifted, 'vm_lifted', 'VM successfully lifted to structured code', trace

        if vm_score >= 5:
            log('static_loadstring', True, 'attempting static loadstring payload extraction')
            try:
                extractor = LoadstringPayloadExtractor(source, decoder)
                payload = extractor.extract()
                if payload and len(payload) > 10 and self._is_valid_lua(payload):
                    renamer = VarRenamer()
                    payload = renamer.rename(payload)
                    payload = beautify(payload)
                    log('static_loadstring', True, f'payload extracted statically ({len(payload)} bytes)')
                    return payload, 'static_loadstring', 'Loadstring payload extracted via static analysis', trace
            except Exception as e:
                log('static_loadstring', False, f'static extraction failed: {str(e)[:100]}')

        log('harness', True, 'attempting static symbolic evaluation')
        harness_result = self.harness.run(source, timeout=120, decoded_strings=decoder.strings)
        if harness_result and len(harness_result) > 100:
            payload = self._extract_payload_from_harness_output(harness_result)
            if payload:
                log('harness_success', True, f'inner payload extracted ({len(payload)} bytes), recursing (fallback)')
                inner_result, inner_method, inner_diag, _ = self.unveil(payload, depth + 1, trace)
                if inner_result and len(inner_result) > 100:
                    return inner_result, f'dynamic_harness+{inner_method}', f'Layer 2: {inner_diag}', trace
            elif self._is_quality_output(harness_result):
                log('harness_success', True, f'symbolic evaluation produced {len(harness_result)} chars')
                return harness_result, 'lua_harness', 'Symbolic evaluation complete', trace

        log('lune_pipeline', True, 'attempting Lune + Darklua extraction pipeline')
        lune_result = run_lune_darklua_pipeline(source)
        if lune_result and looks_like_real_code(lune_result):
            renamer = VarRenamer()
            lune_result = renamer.rename(lune_result)
            lune_result = beautify(lune_result)
            log('lune_pipeline_success', True, f'Lune+Darklua produced {len(lune_result)} chars')
            return lune_result, 'lune_darklua', 'Lune sandbox extraction + Darklua optimization', trace

        log('devirtualise', True, 'dumping instruction table from decoded strings')
        try:
            dumper = InstructionTableDumper(source, decoder.strings)
            dumped = dumper.dump()
            if dumped and len(dumped) > 200:
                log('devirtualise_success', True, 'instruction table dumped with reconstruction')
                return dumped, 'instr_table_dump', 'String table with source reconstruction', trace
        except Exception as e:
            log('devirtualise', False, f'instruction dumper failed: {str(e)[:100]}')

        log('devirtualise', True, 'attempting state-machine lifting via regex')
        sm_lifter = StateMachineLifter(source, decoder.strings, offset=decoder.offset)
        lifted = sm_lifter.lift()
        if lifted and self._is_valid_lua(lifted):
            log('devirtualise_success', True, 'state machine lifted')
            renamer = VarRenamer()
            lifted = renamer.rename(lifted)
            lifted = beautify(lifted)
            return lifted, 'state_machine_lifted', 'State machine lifted', trace

        log('devirtualise', True, 'falling back to static devirtualisation')
        devirt = Devirtualiser(decoder, annotate=True)
        processed = devirt.process(source)
        if processed:
            renamer = VarRenamer()
            result = renamer.rename(processed)
            result = beautify(result)
            header = '-- [VM DETECTED] Devirtualised via fallback\n\n' if devirt.vm_detected else '-- Deobfuscated\n\n'
            return header + result, 'static_analysis', 'Static devirtualisation complete', trace

        log('devirtualise', False, 'all stages failed, returning string dump')
        try:
            dumper = InstructionTableDumper(source, decoder.strings)
            dumped = dumper.dump()
            if dumped:
                return dumped, 'wearedevs_decode', 'Decoded string table (best effort)', trace
        except:
            pass
        lines = [f'-- [{i}] {json.dumps(str(s))}' for i, s in enumerate(decoder.strings) if s]
        return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table', trace

class DeobfEngine:
    def __init__(self) -> None:
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.harness = LuaHarness(unluac_path=self.unluac_path)
        self.var_renamer = VarRenamer()

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            'wearedevs_decode': True,
            'static_analysis': True,
            'lua_harness': self.harness.available,
            'lune_darklua': True,
            'unluac': self._java_available and os.path.isfile(self.unluac_path),
            'var_renamer': True,
            'state_machine_lifter': True,
            'vm_instruction_lifter': True,
            'vm_devirtualizer': True,
            'instruction_table_dumper': True,
            'symbolic_eval': True,
            'static_loadstring': True,
            'prometheus_decode': True,
        }

    def process(self, source: str, logger: Optional[JobLogger] = None) -> Tuple[str, str, str, list]:
        unveiler = Unveiler(harness=self.harness)
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
