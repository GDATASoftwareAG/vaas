class VaasAuthenticationError(BaseException):
    """Authentication Error"""


class VaasTimeoutError(BaseException):
    """Generic timeout"""


class VaasInvalidStateError(BaseException):
    """Invalid state"""


class VaasConnectionClosedError(BaseException):
    """Connection closed"""

class VaasClientError(BaseException):
    """Client Error"""
    def __init__(self, message = None) -> None:
        if message is None:
            super().__init__("Client Error")
        else:
            super().__init__(message)

class VaasServerError(BaseException):
    """Server Error"""
    def __init__(self, message = None) -> None:
        if message is None:
            super().__init__("Server Error")
        else:
            super().__init__(message)
