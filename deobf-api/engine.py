import time
import uuid
import threading
import logging

from anti_tamper import remove_anti_tamper
from beautifier import beautify
from var_renamer import VarRenamer
from string_decoder import StringTableDecoder, is_lua_source
from vm_deobfuscator import run_vm_deobfuscator
from prometheus_decoder import PrometheusDecoder
from unveilr import run_unveilr
from vm_devirtualizer import VMDevirtualizer
from wearedevs_decoder import WeAreDevsDecoder
from prometheus_vm import PrometheusVMDevirtualizer, is_prometheus_vm

log = logging.getLogger(__name__)


class DeobfEngine:
    def __init__(self):
        pass

    def process(self, source):
        trace = []
        renamer = VarRenamer()

        # Stage 1: Remove anti-tamper
        try:
            source = remove_anti_tamper(source)
            if source is None:
                raise ValueError("Anti-tamper returned None")
            trace.append({'stage': 'anti_tamper', 'success': True, 'message': 'Anti-tamper removed'})
        except Exception as e:
            trace.append({'stage': 'anti_tamper', 'success': False, 'message': f'Anti-tamper removal failed: {e}'})

        if not source or len(source) < 10:
            trace.append({'stage': 'fallback', 'success': False, 'message': 'Source empty after anti-tamper'})
            return '', 'failed', 'Unable to deobfuscate - source too short or empty after anti-tamper', trace

        # Stage 1.5: WeAreDevs-specific detection and decoding
        if 'wearedevs.net/obfuscator' in source or 'wearedevs' in source.lower():
            trace.append({'stage': 'wearedevs_detect', 'success': True, 'message': 'WeAreDevs header detected'})
            try:
                wd = WeAreDevsDecoder(source)
                result = wd.decode()
                if result and len(result) > 10:
                    try:
                        result = beautify(result)
                    except Exception as e:
                        trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                    try:
                        result = renamer.rename(result)
                        trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                    except Exception as e:
                        trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                    trace.append({'stage': 'wearedevs_decoder', 'success': True, 'message': 'Deobfuscated via WeAreDevs decoder'})
                    return result, 'wearedevs_decoder', 'Deobfuscated via WeAreDevs-specific decoder', trace
            except Exception as e:
                trace.append({'stage': 'wearedevs_decoder', 'success': False, 'message': f'WeAreDevs decoder error: {e}'})

        # Stage 2: String table decoder (enhanced for WeAreDevs)
        decoder = None
        try:
            decoder = StringTableDecoder(source)
            if decoder.ok:
                result = decoder.get_source()
                if result and len(result) > 10 and is_lua_source(result):
                    try:
                        result = beautify(result)
                    except Exception as e:
                        trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                    try:
                        result = renamer.rename(result)
                        trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                    except Exception as e:
                        trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                    trace.append({'stage': 'string_decoder', 'success': True, 'message': 'String table decoded'})
                    return result, 'string_decoder', 'Deobfuscated via string table extraction', trace
                else:
                    # WeAreDevs: try Prometheus-style assembly even if no single full source
                    if decoder.strings and len(decoder.strings) >= 4:
                        try:
                            prom = PrometheusDecoder(source, decoder)
                            payload = prom.decode()
                            if payload and len(payload) > 10 and is_lua_source(payload):
                                try:
                                    payload = beautify(payload)
                                except Exception:
                                    pass
                                try:
                                    payload = renamer.rename(payload)
                                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                                except Exception as e:
                                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                                trace.append({'stage': 'string_decoder', 'success': True, 'message': 'String table assembled'})
                                return payload, 'string_decoder', 'Deobfuscated via string table assembly', trace
                        except Exception as e:
                            trace.append({'stage': 'prometheus_assembly', 'success': False, 'message': f'Assembly failed: {e}'})
            else:
                trace.append({'stage': 'string_decoder', 'success': False, 'message': 'No string table found'})
        except Exception as e:
            trace.append({'stage': 'string_decoder', 'success': False, 'message': f'String decoder error: {e}'})

        # Stage 3: Try VM deobfuscator (Lua script)
        trace.append({'stage': 'vm_deobfuscator', 'success': True, 'message': 'Attempting VM deobfuscator'})
        try:
            result = run_vm_deobfuscator(source, timeout=60)
            if result and len(result) > 10 and is_lua_source(result):
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                trace.append({'stage': 'vm_deobfuscator', 'success': True, 'message': 'VM deobfuscator succeeded'})
                return result, 'vm_deobfuscator', 'Deobfuscated with VM deobfuscator', trace
            else:
                trace.append({'stage': 'vm_deobfuscator', 'success': False, 'message': 'VM deobfuscator returned empty'})
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
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                trace.append({'stage': 'prometheus_deobfuscator', 'success': True, 'message': 'Prometheus deobfuscator succeeded'})
                return result, 'prometheus_deobfuscator', 'Deobfuscated with Prometheus deobfuscator', trace
            else:
                trace.append({'stage': 'prometheus_deobfuscator', 'success': False, 'message': 'Prometheus returned empty'})
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
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                trace.append({'stage': 'unveilr', 'success': True, 'message': 'Unveilr succeeded'})
                return result, 'unveilr', 'Deobfuscated with Unveilr', trace
            else:
                trace.append({'stage': 'unveilr', 'success': False, 'message': 'Unveilr returned empty'})
        except Exception as e:
            trace.append({'stage': 'unveilr', 'success': False, 'message': f'Error: {str(e)[:200]}'})

        # Stage 5.5: Aggressive VM devirtualizer (WeAreDevs heavy VM)
        trace.append({'stage': 'vm_devirtualizer', 'success': True, 'message': 'Attempting VM devirtualizer'})
        try:
            dev = VMDevirtualizer(source, decoder=decoder if decoder else None)
            result = dev.devirtualize()
            if result and len(result) > 10 and is_lua_source(result):
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                try:
                    result = renamer.rename(result)
                    trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                except Exception as e:
                    trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                trace.append({'stage': 'vm_devirtualizer', 'success': True, 'message': 'VM devirtualizer succeeded'})
                return result, 'vm_devirtualizer', 'Deobfuscated with VM devirtualizer', trace
            else:
                trace.append({'stage': 'vm_devirtualizer', 'success': False, 'message': 'VM devirtualizer returned empty'})
        except Exception as e:
            trace.append({'stage': 'vm_devirtualizer', 'success': False, 'message': f'Error: {str(e)[:200]}'})

        # === NEW Stage 5.75: Prometheus VM Devirtualizer ===
        # This handles heavy Prometheus/WeAreDevs VM state machines
        if is_prometheus_vm(source):
            trace.append({'stage': 'prometheus_vm', 'success': True, 'message': 'Attempting Prometheus VM devirtualizer'})
            try:
                prom_vm = PrometheusVMDevirtualizer(source)
                result = prom_vm.devirtualize()
                if result and len(result) > 10:
                    # Check if result is valid Lua or at least readable code
                    lua_kws = ['function', 'local', 'end', 'return', 'if', 'then', 'else', 'while', 'for', 'do']
                    score = sum(1 for kw in lua_kws if kw in result)
                    if score >= 2 or len(result) > 500:
                        try:
                            result = beautify(result)
                        except Exception as e:
                            trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {e}'})
                        try:
                            result = renamer.rename(result)
                            trace.append({'stage': 'rename', 'success': True, 'message': 'Variables renamed'})
                        except Exception as e:
                            trace.append({'stage': 'rename', 'success': False, 'message': f'Rename failed: {e}'})
                        trace.append({'stage': 'prometheus_vm', 'success': True, 'message': 'Prometheus VM devirtualizer succeeded'})
                        return result, 'prometheus_vm', 'Deobfuscated with Prometheus VM devirtualizer', trace
                    else:
                        trace.append({'stage': 'prometheus_vm', 'success': False, 'message': 'Output did not look like Lua'})
                else:
                    trace.append({'stage': 'prometheus_vm', 'success': False, 'message': 'Prometheus VM returned empty'})
            except Exception as e:
                trace.append({'stage': 'prometheus_vm', 'success': False, 'message': f'Error: {str(e)[:200]}'})
        else:
            trace.append({'stage': 'prometheus_vm', 'success': False, 'message': 'Not a Prometheus VM pattern'})

        # Stage 6: Try to dump raw strings as fallback
        try:
            if decoder and decoder.strings:
                offset = getattr(decoder, 'offset', 0)
                alphabet = decoder.alphabet or 'not found'
                renamed_note = '(alphabet keys were renamed - used standard base64)' if decoder.alphabet_renamed else ''
                result_lines = [
                    f'-- Detected getter offset: {offset}',
                    f'-- Alphabet: {alphabet} {renamed_note}',
                    f'-- Total strings: {len(decoder.strings)}',
                    '',
                ]
                for i, s in enumerate(decoder.strings):
                    if s and is_printable(s):
                        safe = s.replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')
                        result_lines.append(f'-- [{i+1}] "{safe[:200]}"')
                result = '\n'.join(result_lines)
                trace.append({'stage': 'string_dump', 'success': True, 'message': f'Dumped {len(decoder.strings)} strings'})
                return result, 'string_dump', 'Raw string table dump (partial recovery)', trace
        except Exception as e:
            trace.append({'stage': 'string_dump', 'success': False, 'message': f'String dump failed: {e}'})

        # All methods failed
        trace.append({'stage': 'fallback', 'success': False, 'message': 'All deobfuscation methods failed'})
        return '', 'failed', 'Unable to deobfuscate - no recognized pattern found', trace


# In-memory job store for async processing
job_store = {}
job_lock = threading.Lock()


def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing'}

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

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return job_id


def get_job(job_id):
    with job_lock:
        return job_store.get(job_id)
