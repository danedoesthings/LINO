import os
import base64
import json
import traceback
from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()

@app.route('/health')
def health():
    return jsonify({'ok': True, 'version': '3.2.0', 'capabilities': list(engine.get_capabilities())})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    source_b64 = data.get('source_b64', '')
    if not source_b64:
        return jsonify({'error': 'No source_b64 provided'}), 400
    try:
        raw_bytes = base64.b64decode(source_b64)
    except Exception:
        return jsonify({'error': 'Invalid base64 data'}), 400
    if len(raw_bytes) > 5 * 1024 * 1024:
        return jsonify({'error': 'Source exceeds 5MB limit'}), 413
    source_str = raw_bytes.decode('latin-1')
    try:
        result, obf_type, diag, trace = engine.process(source_str)
        return jsonify({
            'result': result,
            'detected': obf_type,
            'diagnostic': diag,
            'trace': trace
        })
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
