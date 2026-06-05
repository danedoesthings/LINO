import os
import base64
import traceback
import logging
import hashlib
import re
import json
import time
import shutil
import tempfile
import subprocess
import signal
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

@app.route('/health')
def health():
    return jsonify({
        'ok': True,
        'version': '10.0.0',
        'capabilities': engine.get_capabilities(),
        'java_available': engine._java_available,
        'unluac_path': engine.unluac_path,
        'unluac_exists': os.path.isfile(engine.unluac_path),
        'has_luaparser': HAS_LUAPARSER,
        'lua_binaries': {
            'lua5.1': '/usr/bin/lua5.1' if os.path.isfile('/usr/bin/lua5.1') else shutil.which('lua5.1'),
            'lua5.2': shutil.which('lua5.2'),
            'lua': shutil.which('lua'),
        },
        'lune_available': shutil.which('lune') is not None,
        'lua51_available': os.path.isfile('/usr/bin/lua5.1') or shutil.which('lua5.1') is not None,
        'lupa_available': _check_lupa(),
    })

@app.route('/alive')
def alive():
    return 'ok'

def _check_lupa():
    try:
        import lupa
        return True
    except ImportError:
        return False

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

@app.route('/deobf/direct', methods=['POST'])
def deobf_direct():
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
    log.info(f"Direct deobf request: {len(raw_bytes)} bytes")
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
        log.error(f"Direct deobf failed: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()[:4000]
        }), 500

@app.route('/deobf', methods=['POST'])
def deobf():
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
    log.info(f"Async deobf request: {len(raw_bytes)} bytes")
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
    job = get_job(job_id)
    if not job:
        return jsonify({
            'error': f'Job not found: {job_id}',
            'tip': 'Use /deobf/direct for synchronous processing'
        }), 404
    if job.get('status') == 'processing':
        elapsed = time.time() - job.get('created', time.time())
        return jsonify({
            'status': 'processing',
            'elapsed_seconds': round(elapsed, 1)
        })
    if job.get('status') == 'error':
        return jsonify({
            'status': 'error',
            'error': job.get('error', 'Unknown error'),
            'traceback': job.get('traceback', '')[:4000]
        }), 500
    return jsonify({
        'status': 'complete',
        'result': job.get('result', ''),
        'detected': job.get('detected', 'unknown'),
        'diagnostic': job.get('diagnostic', ''),
        'trace': job.get('trace', []),
        'result_length': job.get('result_length', 0)
    })

@app.route('/deobf/sync', methods=['POST'])
def deobf_sync():
    return deobf_direct()

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

@app.route('/debug-harness', methods=['POST'])
def debug_harness():
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
    harness = engine.harness

    stdout = ""
    stderr = ""
    exit_code = "0"
    timeout = False

    try:
        from string_decoder import StringTableDecoder
        decoder = StringTableDecoder(source_str)
        harness_output = harness.run(source_str, timeout=120, decoded_strings=decoder.strings if decoder.ok else None)
        if harness_output:
            stdout = harness_output
        else:
            stderr = "Harness returned no output"
            exit_code = "1"
    except Exception as e:
        stderr = str(e) + "\n" + traceback.format_exc()
        exit_code = "1"

    return jsonify({
        'lua_found': harness.available,
        'lua_path': '/usr/bin/lua5.1' if os.path.isfile('/usr/bin/lua5.1') else shutil.which('lua5.1') or shutil.which('lua') or 'not found',
        'lua51_available': os.path.isfile('/usr/bin/lua5.1') or shutil.which('lua5.1') is not None,
        'lune_available': shutil.which('lune') is not None,
        'exit_code': exit_code,
        'timeout': timeout,
        'stdout': stdout[:5000],
        'stderr': stderr[:5000],
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
