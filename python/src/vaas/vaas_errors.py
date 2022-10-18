class VaasAuthenticationError(BaseException):
    """Authentication Error"""


class VaasTimeoutError(BaseException):
    """Generic timeout"""


class VaasInvalidStateError(BaseException):
    """Invalid state"""


class VaasConnectionClosedError(BaseException):
    """Connection closed"""
