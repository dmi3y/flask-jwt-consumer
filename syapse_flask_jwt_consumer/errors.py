# Error handler
class AuthError(Exception):
    """Throws exeptions period."""

    def __init__(self, error, status_code):
        """Initializer period."""
        self.content = error
        self.code = status_code
