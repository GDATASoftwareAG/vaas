from abc import abstractmethod

class AuthenticatorInterface:
    @abstractmethod
    async def get_token(self):
        pass