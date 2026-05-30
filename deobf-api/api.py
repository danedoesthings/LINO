import os
import base64
import traceback
import logging
import hashlib
import re
import json
import time
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import DeobfEngine, submit_job, get_job

try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('deobf-api')

app = Flask(__name__)
CORS(app)

engine = DeobfEngine()

JOB_STORAGE_FILE = '/tmp/deobf_jobs.json'

def _save_jobs():
    try:
        from engine import job_store
        with open(JOB_STORAGE_FILE, 'w') as f:
            json.dump({k: v for k, v in job_store.items() if v.get('status') != 'processing'}, f)
    except Exception as e:
        log.error(f"Failed to save jobs: {e}")

def _load_jobs():
    try:
        if os.path.exists(JOB_STORAGE_FILE):
            with open(JOB_STORAGE_FILE, 'r') as f:
                loaded = json.load(f)
                from engine import job_store
                job_store.update(loaded)
                log.info(f"Loaded {len(loaded)} persisted jobs")
    except Exception as e:
        log.error(f"Failed to load jobs: {e}")

_load_jobs()

@app.route('/health')
def health():
    return jsonify({
        'ok': True,
        'version': '9.0.0',
        'capabilities': engine.get_capabilities(),
        'java_available': engine._java_available,
        'unluac_path': engine.unluac_path,
        'unluac_exists': os.path.isfile(engine.unluac_path),
        'has_luaparser': HAS_LUAPARSER
    })

@app.route('/debug')
def debug():
    try:
        engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'engine.py')
        with open(engine_path, 'r') as f:
            code = f.read()
        sha = hashlib.sha256(code.encode()).hexdigest()[:16]
        return jsonify({'engine_sha': sha, 'engine_size': len(code)})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No JSON data provided', 'usage': 'POST JSON with source_b64 field'}), 400
    
    source_b64 = data.get('source_b64', '')
    if not source_b64:
        return jsonify({'error': 'No source_b64 provided'}), 400
    
    try:
        raw_bytes = base64.b64decode(source_b64)
    except Exception as e:
        return jsonify({'error': f'Invalid base64: {str(e)}'}), 400
    
    if len(raw_bytes) > 5 * 1024 * 1024:
        return jsonify({'error': f'Source exceeds 5MB limit ({len(raw_bytes)} bytes)'}), 413
    
    source_str = raw_bytes.decode('latin-1', errors='replace')
    log.info(f"Deobf request: {len(raw_bytes)} bytes, {len(source_str.splitlines())} lines")
    
    job_id = submit_job(source_str)
    job_id = re.sub(r'\s+', '', job_id)
    
    return jsonify({
        'job_id': job_id,
        'status': 'processing',
        'check_url': f'/deobf/{job_id}'
    })

@app.route('/deobf/<job_id>', methods=['GET'])
def deobf_status(job_id):
    job_id = re.sub(r'\s+', '', job_id)
    log.info(f"Status check for job: {job_id}")
    
    from engine import job_store
    
    if job_id not in job_store:
        _load_jobs()
    
    job = job_store.get(job_id)
    
    if not job:
        return jsonify({
            'error': f'Job not found: {job_id}',
            'tip': 'Jobs expire after completion. Resubmit your file.'
        }), 404
    
    if job.get('status') == 'processing':
        elapsed = time.time() - job.get('created', time.time())
        return jsonify({
            'status': 'processing',
            'elapsed_seconds': round(elapsed, 1),
            'message': 'Deobfuscation in progress...'
        })
    
    if job.get('status') == 'error':
        return jsonify({
            'status': 'error',
            'error': job.get('error', 'Unknown error'),
            'traceback': job.get('traceback', '')[:4000]
        }), 500
    
    result = job.get('result', '')
    detected = job.get('detected', 'unknown')
    diagnostic = job.get('diagnostic', '')
    trace = job.get('trace', [])
    result_length = job.get('result_length', 0)
    
    response = {
        'status': 'complete',
        'result': result,
        'detected': detected,
        'diagnostic': diagnostic,
        'trace': trace,
        'result_length': result_length
    }
    
    return jsonify(response)

@app.route('/deobf/sync', methods=['POST'])
def deobf_sync():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    source_b64 = data.get('source_b64', '')
    if not source_b64:
        return jsonify({'error': 'No source_b64 provided'}), 400
    
    try:
        raw_bytes = base64.b64decode(source_b64)
    except Exception as e:
        return jsonify({'error': f'Invalid base64: {str(e)}'}), 400
    
    if len(raw_bytes) > 5 * 1024 * 1024:
        return jsonify({'error': f'Source exceeds 5MB limit ({len(raw_bytes)} bytes)'}), 413
    
    source_str = raw_bytes.decode('latin-1', errors='replace')
    
    log.info(f"Sync deobf request: {len(raw_bytes)} bytes")
    
    try:
        result, method, diagnostic, trace = engine.process(source_str)
        
        return jsonify({
            'status': 'complete',
            'result': result,
            'detected': method,
            'diagnostic': diagnostic,
            'trace': trace,
            'result_length': len(result) if result else 0
        })
    except Exception as e:
        log.error(f"Sync deobf failed: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()[:4000]
        }), 500

@app.route('/jobs')
def list_jobs():
    from engine import job_store
    jobs = []
    for job_id, job in list(job_store.items())[:50]:
        jobs.append({
            'job_id': job_id,
            'status': job.get('status'),
            'created': job.get('created'),
            'detected': job.get('detected') if job.get('status') == 'complete' else None,
            'result_length': job.get('result_length', 0) if job.get('status') == 'complete' else None
        })
    return jsonify({'jobs': jobs, 'total': len(job_store)})

@app.route('/clear_jobs', methods=['POST'])
def clear_jobs():
    from engine import job_store, job_lock
    with job_lock:
        job_store.clear()
        if os.path.exists(JOB_STORAGE_FILE):
            os.unlink(JOB_STORAGE_FILE)
    return jsonify({'status': 'cleared', 'message': 'All jobs removed'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
