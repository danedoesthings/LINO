import time
import uuid
import threading
from string_decoder import StringTableDecoder
from anti_tamper import remove_anti_tamper
from beautifier import beautify
from run_deobfuscator import run_vm_deobfuscator, run_prometheus_deobfuscator, run_unveilr

class DeobfEngine:
    def process(self, source):
        trace = []
        
        source = remove_anti_tamper(source)
        trace.append({'stage': 'anti_tamper', 'success': True, 'message': 'Anti-tamper removed'})
        
        decoder = StringTableDecoder(source)
        if decoder.ok:
            result = decoder.get_source()
            if result and len(result) > 10:
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}')
                trace.append({'stage': 'beautify', 'success': True, 'message': 'Output beautified'})
                return result, 'success', 'Deobfuscation via string table', trace
        
        trace.append({'stage': 'vm_deobfuscator', 'success': True, 'message': 'Attempting VM deobfuscator'})
        try:
            result = run_vm_deobfuscator(source, timeout=60)
            if result and len(result) > 10:
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}')
                trace.append({'stage': 'beautify', 'success': True, 'message': 'Output beautified'})
                return result, 'success', 'Deobfuscated with VM deobfuscator', trace
            else:
                trace.append({'stage': 'vm_deobfuscator', 'success': False, 'message': 'VM deobfuscator returned empty'})
        except Exception as e:
            trace.append({'stage': 'vm_deobfuscator', 'success': False, 'message': f'Error: {str(e)[:200]}'})
        
        trace.append({'stage': 'prometheus_deobfuscator', 'success': True, 'message': 'Attempting Prometheus deobfuscator'})
        try:
            result = run_prometheus_deobfuscator(source, timeout=120)
            if result and len(result) > 10:
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}')
                trace.append({'stage': 'beautify', 'success': True, 'message': 'Output beautified'})
                return result, 'success', 'Deobfuscated with Prometheus deobfuscator', trace
            else:
                trace.append({'stage': 'prometheus_deobfuscator', 'success': False, 'message': 'Prometheus deobfuscator returned empty'})
        except Exception as e:
            trace.append({'stage': 'prometheus_deobfuscator', 'success': False, 'message': f'Error: {str(e)[:200]}'})
        
        trace.append({'stage': 'unveilr', 'success': True, 'message': 'Attempting Unveilr deobfuscator'})
        try:
            result = run_unveilr(source, timeout=120)
            if result and len(result) > 10:
                try:
                    result = beautify(result)
                except Exception as e:
                    trace.append({'stage': 'beautify', 'success': False, 'message': f'Beautify failed: {str(e)[:100]}')
                trace.append({'stage': 'beautify', 'success': True, 'message': 'Output beautified'})
                return result, 'success', 'Deobfuscated with Unveilr', trace
            else:
                trace.append({'stage': 'unveilr', 'success': False, 'message': 'Unveilr returned empty'})
        except Exception as e:
            trace.append({'stage': 'unveilr', 'success': False, 'message': f'Error: {str(e)[:200]}'})
        
        if decoder.strings:
            offset = getattr(decoder, 'offset', 0)
            alphabet = decoder.alphabet or 'not found'
            result_lines = [f'-- Detected getter offset: {offset}', f'-- Alphabet: {alphabet}', '']
            for i, s in enumerate(decoder.strings):
                if s:
                    result_lines.append(f'-- [{i+1}] "{s}"')
            result = '\n'.join(result_lines)
            trace.append({'stage': 'string_dump', 'success': True, 'message': f'Dumped {len(decoder.strings)} raw strings'})
            return result, 'string_dump', 'Raw string table dump', trace
        
        trace.append({'stage': 'fallback', 'success': False, 'message': 'All deobfuscation methods failed'})
        return '', 'failed', 'Unable to deobfuscate', trace


job_store = {}
job_lock = threading.Lock()

def submit_job(source):
    job_id = str(uuid.uuid4())
    with job_lock:
        job_store[job_id] = {'status': 'processing', 'created': time.time()}
    
    def run():
        engine = DeobfEngine()
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
    
    threading.Thread(target=run, daemon=True).start()
    return job_id

def get_job(job_id):
    with job_lock:
        return job_store.get(job_id)
