import time
import uuid
import threading
import logging

from string_decoder import StringTableDecoder, is_printable, is_lua_source
from anti_tamper import remove_anti_tamper
from beautifier import beautify
from var_renamer import VarRenamer
from run_deobfuscator import run_vm_deobfuscator, run_prometheus_deobfuscator, run_unveilr

log = logging.getLogger('deobf-api')


class DeobfEngine:
    """Orchestrates the deobfuscation pipeline with multiple strategies."""

    def process(self, source):
        trace = []
        renamer = VarRenamer()

        # Stage 1: Remove anti-tamper
        try:
            source = remove_anti_tamper(source)
            trace.append({'stage': 'anti_tamper', 'success': True, 'message': 'Anti-tamper removed'})
        except Exception as e:
            trace.append({'stage': 'anti_tamper', 'success': False, 'message': f'Anti-tamper removal failed: {str(e)[:100]}'})

        # Stage 2: Try string table decoder (most common Prometheus pattern)
        try:
            decoder = StringTableDecoder(source)
            if decoder.ok:
                result = decoder.get_source()
                if result and len(result) > 10:
                    try:
                        result = beautify(result)
                    except Exception as e:
                        trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}'})
                    try:
                        result = renamer.rename(result)
                        trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                    except Exception as e:
                        trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {str(e)[:100]}'})
                    trace.append({'stage': 'string_decoder', 'success': True, 'message': 'String table decoded'})
                    return result, 'string_decoder', 'Deobfuscated via string table extraction', trace
            trace.append({'stage': 'string_decoder', 'success': False, 'message': 'String table not found or empty'})
        except Exception as e:
            trace.append({'stage': 'string_decoder', 'success': False, 'message': f'Error: {str(e)[:200]}'})

        # Stage 3: Try VM deobfuscator (Lua script)
        trace.append({'stage': 'vm_deobfuscator', 'success': True, 'message': 'Attempting VM deobfuscator'})
        try:
            result = run_vm_deobfuscator(source, timeout=60)
            if result and len(result) > 10 and is_lua_source(result):
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {str(e)[:100]}'})
                trace.append({'stage': 'vm_deobfuscator', 'success': True, 'message': 'VM deobfuscator succeeded'})
                return result, 'vm_deobfuscator', 'Deobfuscated with VM deobfuscator', trace
            else:
                trace.append({'stage': 'vm_deobfuscator', 'success': False, 'message': 'VM deobfuscator returned empty or invalid'})
        except Exception as e:
            trace.append({'stage': 'vm_deobfuscator', 'success': False, 'message': f'Error: {str(e)[:200]}'})

        # Stage 4: Try Prometheus deobfuscator (Lua script)
        trace.append({'stage': 'prometheus_deobfuscator', 'success': True, 'message': 'Attempting Prometheus deobfuscator'})
        try:
            result = run_prometheus_deobfuscator(source, timeout=120)
            if result and len(result) > 10 and is_lua_source(result):
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {str(e)[:100]}'})
                trace.append({'stage': 'prometheus_deobfuscator', 'success': True, 'message': 'Prometheus deobfuscator succeeded'})
                return result, 'prometheus_deobfuscator', 'Deobfuscated with Prometheus deobfuscator', trace
            else:
                trace.append({'stage': 'prometheus_deobfuscator', 'success': False, 'message': 'Prometheus deobfuscator returned empty or invalid'})
        except Exception as e:
            trace.append({'stage': 'prometheus_deobfuscator', 'success': False, 'message': f'Error: {str(e)[:200]}'})

        # Stage 5: Try Unveilr
        trace.append({'stage': 'unveilr', 'success': True, 'message': 'Attempting Unveilr deobfuscator'})
        try:
            result = run_unveilr(source, timeout=120)
            if result and len(result) > 10 and is_lua_source(result):
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {str(e)[:100]}'})
                trace.append({'stage': 'unveilr', 'success': True, 'message': 'Unveilr succeeded'})
                return result, 'unveilr', 'Deobfuscated with Unveilr', trace
            else:
                trace.append({'stage': 'unveilr', 'success': False, 'message': 'Unveilr returned empty or invalid'})
        except Exception as e:
            trace.append({'stage': 'unveilr', 'success': False, 'message': f'Error: {str(e)[:200]}'})

        # Stage 6: Try to dump raw strings as fallback
        try:
            decoder = StringTableDecoder(source)
            if decoder.strings:
                offset = getattr(decoder, 'offset', 0)
                alphabet = decoder.alphabet or 'not found'
                result_lines = [
                    f'-- Detected getter offset: {offset}',
                    f'-- Alphabet: {alphabet}',
                    f'-- Total strings: {len(decoder.strings)}',
                    ''
                ]
                for i, s in enumerate(decoder.strings):
                    if s and is_printable(s):
                        safe = s.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('"', '\\"')
                        result_lines.append(f'-- [{i+1}] "{safe[:200]}"')
                result = '\n'.join(result_lines)
                trace.append({'stage': 'string_dump', 'success': True, 'message': f'Dumped {len(decoder.strings)} raw strings'})
                return result, 'string_dump', 'Raw string table dump (partial recovery)', trace
        except Exception as e:
            trace.append({'stage': 'string_dump', 'success': False, 'message': f'String dump failed: {str(e)[:100]}'})

        # All methods failed
        trace.append({'stage': 'fallback', 'success': False, 'message': 'All deobfuscation methods failed'})
        return '', 'failed', 'Unable to deobfuscate - no recognized pattern found', trace


# In-memory job store for async processing
job_store = {}
job_lock = threading.Lock()


def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}

    def run():
        engine = DeobfEngine()
        try:
            result, method, diag, trace = engine.process(source)
            with job_lock:
                job_store[job_id] = {
                    'status': 'complete',
                    'result': result,
                    'detected': method,
                    'diagnostic': diag,
                    'trace': trace,
                    'result_length': len(result)
                }
        except Exception as e:
            log.error(f"Job {job_id} failed: {e}")
            with job_lock:
                job_store[job_id] = {
                    'status': 'complete',
                    'result': '',
                    'detected': 'error',
                    'diagnostic': f'Job failed: {str(e)}',
                    'trace': [{'stage': 'job', 'success': False, 'message': str(e)}],
                    'result_length': 0
                }

    threading.Thread(target=run, daemon=True).start()
    return job_id


def get_job(job_id):
    with job_lock:
        return job_store.get(job_id)
