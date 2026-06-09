import time
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TraceEntry:
    """A single pipeline stage trace entry."""
    stage: str
    success: bool
    message: str
    detail: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            'stage': self.stage,
            'success': self.success,
            'message': self.message,
            'detail': self.detail,
            'elapsed_ms': round((time.time() - self.ts) * 1000, 1),
        }


class JobLogger:
    """Logger for deobfuscation job tracing."""

    def __init__(self, verbose: bool = False, job_id: str = '') -> None:
        self.verbose = verbose
        self.job_id = job_id
        self._traces: list[TraceEntry] = []
        self._errors: list[dict] = []
        self._start: float = time.time()
        self._result: Optional[str] = None
        self._method: str = ''
        self._diagnostic: str = ''
        self._capabilities: dict = {}

    def start(self, capabilities: Optional[dict] = None) -> None:
        self._start = time.time()
        self._capabilities = capabilities or {}
        self._emit(f'[JOB {self.job_id}] started')

    def log(self, stage: str, success: bool, message: str, **detail: Any) -> None:
        entry = TraceEntry(stage=stage, success=success, message=message, detail=dict(detail))
        self._traces.append(entry)
        icon = 'v' if success else 'x'
        self._emit(f' {icon} [{stage}] {message}')

    def add_error(self, msg: str, exc: Optional[Exception] = None) -> None:
        self._errors.append({'message': msg, 'exception': str(exc) if exc else None})
        self._emit(f' !! ERROR: {msg}', error=True)

    def finish(self, result: Optional[str] = None, method: str = '', diagnostic: str = '') -> None:
        self._result = result
        self._method = method
        self._diagnostic = diagnostic
        elapsed = round((time.time() - self._start) * 1000, 1)
        sz = len(result) if result else 0
        self._emit(f'[JOB {self.job_id}] finished method={method!r} output_chars={sz} elapsed={elapsed}ms')

    def to_json(self) -> str:
        return json.dumps({
            'job_id': self.job_id,
            'method': self._method,
            'diagnostic': self._diagnostic,
            'output_chars': len(self._result) if self._result else 0,
            'elapsed_ms': round((time.time() - self._start) * 1000, 1),
            'capabilities': self._capabilities,
            'trace': [e.to_dict() for e in self._traces],
            'errors': self._errors,
        }, indent=2)

    def _emit(self, msg: str, error: bool = False) -> None:
        if self.verbose:
            out = sys.stderr if error else sys.stdout
            print(msg, file=out)

    def add_trace(self, stage: str, success: bool, message: str) -> None:
        self.log(stage, success, message)
