import os
import base64
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import DeobfEngine, submit_job, get_job

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
log = logging.getLogger('deobf-api')

app = Flask(__name__)
CORS(app)
engine = DeobfEngine()

@app.route('/health')
def health():
    return jsonify({'ok': True, 'version': '1.0.0'})

@app.route('/deobf/direct', methods=['POST', 'OPTIONS'])
def deobf_direct():
    if request.method == 'OPTIONS':
        return '', 200
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data'}), 400
    
    source_b64 = data.get('source_b64', '')
    if not source_b64:
        return jsonify({'error': 'No source_b64'}), 400
    
    try:
        source = base64.b64decode(source_b64).decode('latin-1')
    except Exception as e:
        return jsonify({'error': f'Invalid base64: {e}'}), 400
    
    if len(source) > 10 * 1024 * 1024:
        return jsonify({'error': 'Source too large'}), 413
    
    log.info(f"Processing {len(source)} bytes")
    result, method, diag, trace = engine.process(source)
    
    return jsonify({
        'status': 'complete',
        'result': result,
        'detected': method,
        'diagnostic': diag,
        'trace': trace,
        'result_length': len(result)
    })

@app.route('/deobf', methods=['POST'])
def deobf_async():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data'}), 400
    
    source_b64 = data.get('source_b64', '')
    if not source_b64:
        return jsonify({'error': 'No source_b64'}), 400
    
    try:
        source = base64.b64decode(source_b64).decode('latin-1')
    except Exception as e:
        return jsonify({'error': f'Invalid base64: {e}'}), 400
    
    job_id = submit_job(source)
    return jsonify({'job_id': job_id, 'status': 'processing'})

@app.route('/deobf/<job_id>', methods=['GET'])
def deobf_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    if job['status'] == 'processing':
        return jsonify({'status': 'processing'})
    
    return jsonify({
        'status': 'complete',
        'result': job.get('result', ''),
        'detected': job.get('detected', ''),
        'diagnostic': job.get('diagnostic', ''),
        'trace': job.get('trace', []),
        'result_length': job.get('result_length', 0)
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
