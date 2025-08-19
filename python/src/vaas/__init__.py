"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""

__version__ = "0.0.1"
__all__ = [
    "Vaas",
    "VaasTracing",
    "VaasAuthenticationError",
    "ClientCredentialsGrantAuthenticator",
    "ResourceOwnerPasswordGrantAuthenticator",
]

__author__ = "G DATA CyberDefense AG <oem@gdata.de>"

from .vaas import Vaas, VaasTracing
from .vaas_errors import (
    VaasAuthenticationError,
)
from .authentication.client_credentials_grant_authenticator import ClientCredentialsGrantAuthenticator
from .authentication.resource_owner_password_grant_authenticator import ResourceOwnerPasswordGrantAuthenticator
