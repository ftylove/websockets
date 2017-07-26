"""
The :mod:`websockets.extensions.base` defines abstract classes for extensions.

See https://tools.ietf.org/html/rfc6455#section-9.

"""


class ClientExtensionFactory:
    """
    Abstract class for client-side extension factories.

    Extension factories handle configuration and negotiation.

    """
    name = ...

    def __init__(self, **kwargs):
        """
        Configure the extension factory.

        For forwards-compatibility, __init__ must accept arbitrary kwargs.

        """

    def get_request_params(self):
        """
        Build request parameters.

        """

    def process_response_params(self, params):
        """"
        Process response parameters.

        Return an extension instance.

        """


class ServerExtensionFactory:
    """
    Abstract class for server-side extension factories.

    Extension factories handle configuration and negotiation.

    """
    name = ...

    def __init__(self, **kwargs):
        """
        Configure the extension factory.

        For forwards-compatibility, __init__ must accept arbitrary kwargs.

        """

    def process_request_params(self, params):
        """"
        Process request parameters.

        Return response params and an extension instance.

        """


class Extension:
    """
    Abstract class for extensions.

    """

    def decode(self, frame):
        """
        Decode an incoming frame.

        """
        return frame

    def encode(self, frame):
        """
        Encode an outgoing frame.

        """
        return frame
