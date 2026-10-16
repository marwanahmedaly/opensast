class VerificationError(RuntimeError):
    """A transport or schema error; never a security verdict."""

    def __init__(self, message: str, *, attempt_log: list[dict] | None = None,
                 prompt: str | None = None, prompt_hash: str | None = None,
                 model: str | None = None) -> None:
        super().__init__(message)
        self.attempt_log = attempt_log or []
        self.prompt = prompt
        self.prompt_hash = prompt_hash
        self.model = model
