import unittest
import xmlrunner

from tests.test_vaas import VaasTest  # pylint: disable=unused-import
from tests.test_client_credentials_grant_authenticator import (
    ClientCredentialsGrantAuthenticatorTest,
)  # pylint: disable=unused-import

if __name__ == "__main__":
    unittest.main(testRunner=xmlrunner.XMLTestRunner(output="test-reports"))
