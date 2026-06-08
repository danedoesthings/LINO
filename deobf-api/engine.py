import re
import time
import uuid
import threading
from string_decoder import StringTableDecoder
from anti_tamper import remove_anti_tamper
from beautifier import beautify
from run_unveilr import run_unveilr

class DeobfEngine:
    def process(self, source):
        trace = []
        
        source = remove_anti_tamper(source)
        trace.append({'stage': 'anti_tamper', 'success': True, 'message': 'Anti-tamper removed'})
        
        decoder = StringTableDecoder(source)
        if decoder.decode():
            result = decoder.get_source()
            if result and len(result) > 10:
                result = beautify(result)
                trace.append({'stage': 'beautify', 'success': True, 'message': 'Output beautified'})
                return result, 'success', 'Deobfuscation via string table', trace
        
        trace.append({'stage': 'unveilr', 'success': True, 'message': 'Attempting Unveilr deobfuscator'})
        try:
            result = run_unveilr(source, timeout=120)
            if result and len(result) > 10:
                result = beautify(result)
                trace.append({'stage': 'beautify', 'success': True, 'message': 'Output beautified'})
                return result, 'success', 'Deobfuscated with Unveilr', trace
            else:
                trace.append({'stage': 'unveilr', 'success': False, 'message': 'Unveilr returned empty result'})
        except Exception as e:
            trace.append({'stage': 'unveilr', 'success': False, 'message': f'Unveilr error: {str(e)[:200]}'})
        
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
