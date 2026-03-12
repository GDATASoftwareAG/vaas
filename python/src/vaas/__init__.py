"""Verdict-as-a-Service

:mod:`vaas` is a Python library for the VaaS-API."""

__version__ = "0.0.1"
__all__ = [
    "Vaas",
    "VaasTracing",
    "VaasOptions",
    "VaasAuthenticationError",
    "VaasClientError",
    "VaasServerError",
    "FromStreamOptions",
    "ForFileOptions",
    "ForSha256Options",
    "ForUrlOptions",
    "ClientCredentialsGrantAuthenticator",
    "ResourceOwnerPasswordGrantAuthenticator",
]

__author__ = "G DATA CyberDefense AG <oem@gdata.de>"

from .vaas import Vaas, VaasTracing, VaasOptions
from .options.for_stream_options import ForStreamOptions
from .options.for_file_options import ForFileOptions
from .options.for_sha256_options import ForSha256Options
from .options.for_url_options import ForUrlOptions
from .vaas_errors import (
    VaasAuthenticationError,
    VaasClientError,
    VaasServerError
)
from .authentication.client_credentials_grant_authenticator import ClientCredentialsGrantAuthenticator
from .authentication.resource_owner_password_grant_authenticator import ResourceOwnerPasswordGrantAuthenticator
