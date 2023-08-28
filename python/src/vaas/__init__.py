"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""

__version__ = "0.0.1"
__all__ = [
    "Vaas",
    "VaasTracing",
    "VaasTimeoutError",
    "VaasAuthenticationError",
    "VaasInvalidStateError",
    "VaasConnectionClosedError",
    "VaasOptions",
    "ClientCredentialsGrantAuthenticator",
    "ResourceOwnerPasswordGrantAuthenticator",
    "get_ssl_context",
]

__author__ = "G DATA CyberDefense AG <oem@gdata.de>"

from .vaas import Vaas, VaasTracing, VaasOptions, get_ssl_context
from .vaas_errors import (
    VaasTimeoutError,
    VaasAuthenticationError,
    VaasInvalidStateError,
    VaasConnectionClosedError,
)
from .client_credentials_grant_authenticator import ClientCredentialsGrantAuthenticator
from .resource_owner_password_grant_authenticator import ResourceOwnerPasswordGrantAuthenticator
