import os, time, uuid, threading, json, traceback
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from string_decoder import StringTableDecoder
from prometheus_decoder import PrometheusDecoder
from var_renamer import VarRenamer
from beautifier import beautify
from env_logger import JobLogger

JOB_STORAGE_DIR = '/data'
JOB_STORAGE_FILE = os.path.join(JOB_STORAGE_DIR, 'deobf_jobs.json')
os.makedirs(JOB_STORAGE_DIR, exist_ok=True)

@dataclass
class DiagnosticEvent:
    stage: str
    success: bool
    message: str
    timestamp: float = field(default_factory=time.time)

class Unveiler:
    def __init__(self) -> None:
        pass

    def unveil(self, source: str, trace: list = None) -> Tuple[str, str, str, list]:
        if trace is None:
            trace = []
        def log(stage, success, message):
            trace.append({'stage': stage, 'success': success, 'message': message, 'timestamp': time.time()})

        decoder = StringTableDecoder(source)
        if not decoder.ok:
            log('decode', False, decoder.diagnostics.get('error', 'decode failed'))
            return '', 'unable', 'String decode failed', trace
        log('decode', True, f'decoded {len(decoder.strings)} strings')

        try:
            prom_decoder = PrometheusDecoder(source, decoder)
            result = prom_decoder.decode()
            if result and len(result) > 10:
                renamer = VarRenamer()
                result = renamer.rename(result)
                result = beautify(result)
                log('prometheus_decode', True, f'decoded {len(result)} chars')
                return result, 'prometheus_decode', 'Prometheus static decode complete', trace
        except Exception as e:
            log('prometheus_decode', False, f'decode failed: {str(e)[:100]}')

        try:
            lines = []
            for i, s in enumerate(decoder.strings):
                if s:
                    lines.append(f'-- [{i+1}] {json.dumps(s)}')
            lines.append('')
            lines.append(f'-- Detected getter offset: {decoder.offset}')
            lines.append('-- Could not fully reconstruct original source')
            return '\n'.join(lines), 'string_table', 'Decoded string table (best effort)', trace
        except:
            return '', 'unable', 'All decode stages failed', trace

class DeobfEngine:
    def __init__(self) -> None:
        self.var_renamer = VarRenamer()

    def get_capabilities(self) -> Dict[str, Any]:
        return {
            'prometheus_decode': True,
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
