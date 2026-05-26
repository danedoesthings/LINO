import os
import base64
import traceback
import logging
import hashlib
import re
from flask import Flask, request, jsonify
from engine import DeobfEngine

try:
    from luaparser import ast as lua_ast
    HAS_LUAPARSER = True
except ImportError:
    HAS_LUAPARSER = False

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger('deobf-api')

app = Flask(__name__)
engine = DeobfEngine()

@app.route('/health')
def health():
    return jsonify({
        'ok': True,
        'version': '7.0.0',
        'capabilities': engine.get_capabilities(),
        'java_available': engine._java_available,
        'unluac_path': engine.unluac_path,
        'unluac_exists': os.path.isfile(engine.unluac_path),
        'has_luaparser': HAS_LUAPARSER
    })

@app.route('/debug')
def debug():
    engine_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'engine.py')
    try:
        with open(engine_path, 'r') as f:
            code = f.read()
        sha = hashlib.sha256(code.encode()).hexdigest()[:16]
        return jsonify({
            'engine_sha': sha,
            'engine_size': len(code)
        })
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

    source_str = raw_bytes.decode('latin-1')
    log.info(f"Deobf request: {len(raw_bytes)} bytes, {len(source_str.splitlines())} lines")

    try:
        result, obf_type, diag, trace = engine.process(source_str)
    except Exception as e:
        tb = traceback.format_exc()
        log.error(f"Deobf failed: {e}\n{tb}")
        return jsonify({'error': str(e), 'traceback': tb[:4000]}), 500

    return jsonify({
        'result': result,
        'detected': obf_type,
        'diagnostic': diag,
        'trace': trace,
        'result_length': len(result) if result else 0
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
