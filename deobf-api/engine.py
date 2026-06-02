import os, re, shutil, time, uuid, threading, json, traceback, subprocess, tempfile, base64, urllib.request
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

from string_decoder import StringTableDecoder
from devirtualiser import Devirtualiser, strip_bootstrap
from state_machine_devirt import StateMachineLifter
from vm_devirtualizer import VMDevirtualizer
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
        self.trace: List[Dict] = []

    def _log(self, stage: str, success: bool, message: str) -> None:
        self.trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})

    def _is_valid_lua(self, code: str) -> bool:
        if not HAS_LUAPARSER:
            return True
        try:
            lua_ast.parse(code)
            return True
        except Exception:
            return False

    def unveil(self, source: str) -> Tuple[str, str, str]:
        self.trace = []
        decoder = StringTableDecoder(source)
        if not decoder.ok:
            self._log('decode', False, decoder.diagnostics.get('error', 'decode failed'))
            return '', 'unable', 'String decode failed'
        self._log('decode', True, f'decoded {len(decoder.strings)} strings')

        self._log('harness', True, 'executing Lua harness')
        harness_result = self.harness.run(source)
        if harness_result and looks_like_real_code(harness_result):
            self._log('harness_success', True, f'captured {len(harness_result)} chars')
            return harness_result, 'lua_harness', 'Harness captured original source'

        self._log('lune_pipeline', True, 'attempting Lune + Darklua extraction pipeline')
        lune_result = run_lune_darklua_pipeline(source)
        if lune_result and looks_like_real_code(lune_result):
            renamer = VarRenamer()
            lune_result = renamer.rename(lune_result)
            lune_result = beautify(lune_result)
            self._log('lune_pipeline_success', True, f'Lune+Darklua produced {len(lune_result)} chars')
            return lune_result, 'lune_darklua', 'Lune sandbox extraction + Darklua optimization'

        self._log('devirtualise', True, 'attempting AST-based VM devirtualization')
        vm_devirt = VMDevirtualizer(source, decoder)
        lifted = vm_devirt.devirtualize()
        if lifted and self._is_valid_lua(lifted):
            self._log('devirtualise_success', True, f'VM lifted, {len(vm_devirt.states)} states processed')
            renamer = VarRenamer()
            lifted = renamer.rename(lifted)
            lifted = beautify(lifted)
            return lifted, 'vm_lifted', 'VM successfully devirtualized to structured code'
        else:
            diag_msg = '; '.join(vm_devirt.diagnostics) if vm_devirt.diagnostics else 'no diagnostics'
            self._log('devirtualise', False, f'VM devirtualizer failed: {diag_msg}')

        self._log('devirtualise', True, 'attempting state-machine lifting via regex')
        sm_lifter = StateMachineLifter(source, decoder.strings, offset=decoder.offset)
        lifted = sm_lifter.lift()
        if lifted and self._is_valid_lua(lifted):
            self._log('devirtualise_success', True, 'state machine lifted')
            renamer = VarRenamer()
            lifted = renamer.rename(lifted)
            lifted = beautify(lifted)
            return lifted, 'state_machine_lifted', 'State machine lifted'

        self._log('devirtualise', True, 'attempting instruction-level VM lifting')
        vm_lifter = WeAreDevsVMLifter(decoder.strings)
        lifted = vm_lifter.lift(source)
        if lifted and self._is_valid_lua(lifted):
            renamer = VarRenamer()
            lifted = renamer.rename(lifted)
            lifted = beautify(lifted)
            self._log('devirtualise_success', True, 'VM lifted via instruction decoder')
            return lifted, 'vm_lifted', 'VM successfully lifted to structured code'

        self._log('devirtualise', True, 'falling back to static devirtualisation')
        devirt = Devirtualiser(decoder, annotate=True)
        processed = devirt.process(source)
        if processed:
            renamer = VarRenamer()
            result = renamer.rename(processed)
            result = beautify(result)
            header = '-- [VM DETECTED] Devirtualised via fallback\n\n' if devirt.vm_detected else '-- Deobfuscated via static analysis\n\n'
            return header + result, 'static_analysis', 'Static devirtualisation complete'

        self._log('devirtualise', False, 'static analysis produced no meaningful output')
        lines = [f'-- [{i}] {json.dumps(str(s))}' for i, s in enumerate(decoder.strings) if s]
        return '\n'.join(lines), 'wearedevs_decode', 'Decoded string table'

class DeobfEngine:
    def __init__(self) -> None:
        self.unluac_path = UNLUAC_LOCAL_PATH
        self._java_available = shutil.which('java') is not None
        self.harness = LuaHarness(unluac_path=self.unluac_path)
        self.unveiler = Unveiler(harness=self.harness)
        self.var_renamer = VarRenamer()
        self.trace: List[DiagnosticEvent] = []

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
        }

    def _trace(self, stage: str, success: bool, message: str) -> None:
        self.trace.append(DiagnosticEvent(stage=stage, success=success, message=message))

    def process(self, source: str, logger: Optional[JobLogger] = None) -> Tuple[str, str, str, list]:
        self.trace = []
        result, method, diagnostic = self.unveiler.unveil(source)
        for entry in self.unveiler.trace:
            self._trace(entry['stage'], entry['success'], entry['message'])
        if logger:
            for entry in self.unveiler.trace:
                logger.add_trace(entry['stage'], entry['success'], entry['message'])
            logger.finish(result, method, diagnostic)
        return result, method, diagnostic, [vars(t) for t in self.trace]

job_store: Dict[str, Any] = {}
job_lock = threading.Lock()

def _save_jobs() -> None:
    try:
        completed = {k: v for k, v in job_store.items() if v.get('status') != 'processing'}
        with open(JOB_STORAGE_FILE, 'w') as f:
            json.dump(completed, f)
    except Exception:
        pass

def _load_jobs() -> None:
    try:
        if os.path.exists(JOB_STORAGE_FILE):
            with open(JOB_STORAGE_FILE) as f:
                job_store.update(json.load(f))
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
    logger.start_job(job_id, engine.get_capabilities())
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
        _load_jobs()
        return job_store.get(job_id)
