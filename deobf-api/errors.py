class LinoError(Exception):
    def __init__(
        self,
        stage,
        message,
        code_snippet=None,
        line=None,
        column=None,
        transformer=None,
        original_exception=None,
        confidence=None,
        recovery_attempted=False,
        recovery_success=False
    ):
        self.stage = stage
        self.message = message
        self.code_snippet = code_snippet
        self.line = line
        self.column = column
        self.transformer = transformer
        self.original_exception = original_exception
        self.confidence = confidence
        self.recovery_attempted = recovery_attempted
        self.recovery_success = recovery_success

        super().__init__(self.__str__())

    def __str__(self):
        return (
            f"[{self.stage}] {self.message} "
            f"(line={self.line}, col={self.column}, "
            f"transformer={self.transformer})"
        )

    def to_dict(self):
        return {
            "stage": self.stage,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "transformer": self.transformer,
            "confidence": self.confidence,
            "recovery_attempted": self.recovery_attempted,
            "recovery_success": self.recovery_success,
            "code_snippet": self.code_snippet
        }
