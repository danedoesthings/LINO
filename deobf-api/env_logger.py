import os
import json
import time
import platform
import traceback
from typing import Optional, Dict, Any

try:
    import psutil
except ImportError:
    psutil = None

class JobLogger:
    def __init__(self):
        self.job_id = None
        self.start_time = None
        self.end_time = None
        self.result = None
        self.method = None
        self.diagnostic = None
        self.trace = []
        self.errors = []
        self.warnings = []
        self.engine_capabilities = {}
        self.environment = {}
        self.memory_start = 0
        self.memory_end = 0

    def start_job(self, job_id, engine_caps):
        self.job_id = job_id
        self.start_time = time.time()
        self.engine_capabilities = engine_caps
        if psutil:
            self.memory_start = psutil.Process().memory_info().rss
        self._collect_environment()

    def _collect_environment(self):
        self.environment = {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'lua_version': self._get_lua_version(),
            'java_available': self.engine_capabilities.get('java_available', False),
            'unluac_path': self.engine_capabilities.get('unluac_path', ''),
            'unluac_exists': os.path.isfile(self.engine_capabilities.get('unluac_path', '')) if self.engine_capabilities.get('unluac_path') else False,
            'luaparser_available': self.engine_capabilities.get('luaparser', False),
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
            'cpu_count': os.cpu_count(),
            'memory_total': psutil.virtual_memory().total if psutil else 0,
            'memory_available': psutil.virtual_memory().available if psutil else 0,
            'disk_free': psutil.disk_usage('/').free if psutil else 0,
            'env_vars': {k: v for k, v in os.environ.items() if not k.startswith('DISCORD')},
        }

    def _get_lua_version(self):
        import subprocess
        try:
            r = subprocess.run(['lua5.1', '-v'], capture_output=True, text=True, timeout=2)
            return r.stdout.strip() or r.stderr.strip() or 'lua5.1 installed'
        except FileNotFoundError:
            try:
                r = subprocess.run(['lua', '-v'], capture_output=True, text=True, timeout=2)
                return r.stdout.strip() or r.stderr.strip() or 'lua installed'
            except:
                return 'not found'

    def add_trace(self, stage, success, message):
        self.trace.append({
            'stage': stage,
            'success': success,
            'message': message,
            'time': round(time.time() - self.start_time, 4)
        })

    def add_error(self, error, exception=None):
        entry = {
            'error': error,
            'time': round(time.time() - self.start_time, 4)
        }
        if exception:
            entry['exception_type'] = type(exception).__name__
            entry['traceback'] = traceback.format_exc()
        self.errors.append(entry)

    def add_warning(self, warning):
        self.warnings.append({
            'warning': warning,
            'time': round(time.time() - self.start_time, 4)
        })

    def finish(self, result=None, method=None, diagnostic=None):
        self.end_time = time.time()
        self.result = result
        self.method = method
        self.diagnostic = diagnostic
        if psutil:
            self.memory_end = psutil.Process().memory_info().rss

    def to_dict(self):
        duration = self.end_time - self.start_time if self.end_time and self.start_time else 0
        memory_delta = self.memory_end - self.memory_start if self.memory_end and self.memory_start else 0
        return {
            'job_id': self.job_id,
            'duration': round(duration, 4),
            'start_time': self.start_time,
            'end_time': self.end_time,
            'result_length': len(self.result) if self.result else 0,
            'method': self.method,
            'diagnostic': self.diagnostic,
            'trace': self.trace,
            'errors': self.errors,
            'warnings': self.warnings,
            'engine_capabilities': self.engine_capabilities,
            'environment': self.environment,
            'memory_start_bytes': self.memory_start,
            'memory_end_bytes': self.memory_end,
            'memory_delta_bytes': memory_delta,
            'trace_stages': [t['stage'] for t in self.trace],
            'failed_stages': [t['stage'] for t in self.trace if not t['success']],
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, default=str)

    def summary(self):
        d = self.to_dict()
        lines = []
        lines.append(f"Job: {d['job_id']}")
        lines.append(f"Duration: {d['duration']}s")
        lines.append(f"Method: {d['method']}")
        lines.append(f"Result: {d['result_length']} chars")
        lines.append(f"Errors: {d['error_count']}")
        lines.append(f"Warnings: {d['warning_count']}")
        lines.append(f"Memory Delta: {d['memory_delta_bytes']} bytes")
        lines.append(f"Pipeline: {' -> '.join(d['trace_stages'])}")
        if d['failed_stages']:
            lines.append(f"Failed: {', '.join(d['failed_stages'])}")
        return '\n'.join(lines)
