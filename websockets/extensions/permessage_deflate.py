"""
The :mod:`websockets.extensions.permessage_deflate` module implements the
Compression Extensions for WebSocket as specified in `RFC 7692`_.

.. _RFC 7692: http://tools.ietf.org/html/rfc7692

"""

import zlib

from ..exceptions import (DuplicateParameter, InvalidParameterName,
                          InvalidParameterValue, NegotiationError)
from ..framing import CTRL_OPCODES, OP_CONT


__all__ = ['PerMessageDeflate']

_EMPTY_UNCOMPRESSED_BLOCK = b'\x00\x00\xff\xff'


def _build_parameters(
    server_no_context_takeover,
    client_no_context_takeover,
    server_max_window_bits,
    client_max_window_bits,
):
    params = []
    if server_no_context_takeover:
        params.append(('server_no_context_takeover', None))
    if client_no_context_takeover:
        params.append(('client_no_context_takeover', None))
    if server_max_window_bits:
        params.append(('server_max_window_bits', str(server_max_window_bits)))
    if client_max_window_bits is True:      # only possible on the client-side
        params.append(('client_max_window_bits', None))
    elif client_max_window_bits:
        params.append(('client_max_window_bits', str(client_max_window_bits)))
    return params


def _extract_parameters(params, *, is_server):
    server_no_context_takeover = False
    client_no_context_takeover = False
    server_max_window_bits = None
    client_max_window_bits = None

    for name, value in params:

        if name == 'server_no_context_takeover':
            if server_no_context_takeover:
                raise DuplicateParameter(name)
            if value is None:
                server_no_context_takeover = True
            else:
                raise InvalidParameterValue(name, value)

        elif name == 'client_no_context_takeover':
            if client_no_context_takeover:
                raise DuplicateParameter(name)
            if value is None:
                client_no_context_takeover = True
            else:
                raise InvalidParameterValue(name, value)

        elif name == 'server_max_window_bits':
            if server_max_window_bits is not None:
                raise DuplicateParameter(name)
            try:
                server_max_window_bits = int(value)
            except ValueError:
                raise InvalidParameterValue(name, value)
            if not 8 <= server_max_window_bits <= 15:
                raise InvalidParameterValue(name, value)

        elif name == 'client_max_window_bits':
            if client_max_window_bits is not None:
                raise DuplicateParameter(name)
            if is_server and value is None:
                client_max_window_bits = True
            else:
                try:
                    client_max_window_bits = int(value)
                except ValueError:
                    raise InvalidParameterValue(name, value)
                if not 8 <= client_max_window_bits <= 15:
                    raise InvalidParameterValue(name, value)

        else:
            raise InvalidParameterName(name)

    return (
        server_no_context_takeover,
        client_no_context_takeover,
        server_max_window_bits,
        client_max_window_bits,
    )


class ClientPerMessageDeflateFactory:
    """
    Client-side extension factory for permessage-deflate extension.

    """
    name = 'permessage-deflate'

    def __init__(
        self,
        server_no_context_takeover=False,
        client_no_context_takeover=False,
        server_max_window_bits=None,
        client_max_window_bits=None,
        **kwargs,
    ):
        """
        Configure permessage-deflate extension factory.

        See https://tools.ietf.org/html/rfc7692#section-7.1.

        """
        if not (server_max_window_bits is None or
                8 <= server_max_window_bits <= 15):
            raise ValueError("server_max_window_bits must be between 8 and 15")
        if not (client_max_window_bits is None or
                client_max_window_bits is True or
                8 <= client_max_window_bits <= 15):
            raise ValueError("client_max_window_bits must be between 8 and 15")

        self.server_no_context_takeover = server_no_context_takeover
        self.client_no_context_takeover = client_no_context_takeover
        self.server_max_window_bits = server_max_window_bits
        self.client_max_window_bits = client_max_window_bits

    def get_request_params(self):
        """
        Build request parameters.

        """
        return _build_parameters(
            self.server_no_context_takeover, self.client_no_context_takeover,
            self.server_max_window_bits, self.client_max_window_bits,
        )

    def process_response_params(self, params):
        """"
        Process response parameters.

        Return an extension instance.

        """
        (
            server_no_context_takeover,
            client_no_context_takeover,
            server_max_window_bits,
            client_max_window_bits,
        ) = _extract_parameters(params, is_server=False)

        # > It is RECOMMENDED that a server supports the
        # > "server_no_context_takeover" extension parameter.

        # If we request server_no_context_takeover (non default) and the
        # server doesn't accept it, we treat that as a negotiation failure.

        if self.server_no_context_takeover and not server_no_context_takeover:
            raise NegotiationError("Expected server_no_context_takeover")

        # > A client MUST support the "client_no_context_takeover" extension
        # > parameter.

        # If we announced client_no_context_takeover, we must honor it even if
        # the server didn't repeat it in its response.

        if self.client_no_context_takeover and not client_no_context_takeover:
            client_no_context_takeover = True

        # > A server accepts an extension negotiation offer with this
        # > parameter by including the "server_max_window_bits" extension
        # > parameter in the extension negotiation response to send back to
        # > the client with the same or smaller value as the offer.

        if self.server_max_window_bits:
            if server_max_window_bits is None:
                raise NegotiationError("Expected server_max_window_bits")
            elif server_max_window_bits > self.server_max_window_bits:
                raise NegotiationError("Unsupported server_max_window_bits")

        # > If a received extension negotiation offer has the
        # > "client_max_window_bits" extension parameter, the server MAY
        # > include the "client_max_window_bits" extension parameter in the
        # > corresponding extension negotiation response to the offer.

        if self.client_max_window_bits is True:
            pass

        # > If the "client_max_window_bits" extension parameter in a received
        # > extension negotiation offer has a value, the server may either
        # > ignore this value or use this value (...) by including the
        # > "client_max_window_bits" extension parameter in the corresponding
        # > extension negotiation response to the offer with a value equal to
        # > or smaller than the received value.

        elif self.client_max_window_bits:
            if client_max_window_bits is None:
                client_max_window_bits = self.client_max_window_bits
            elif client_max_window_bits > self.client_max_window_bits:
                raise NegotiationError("Unsupported client_max_window_bits")

        # > If a received extension negotiation offer doesn't have the
        # > "client_max_window_bits" extension parameter, the corresponding
        # > extension negotiation response to the offer MUST NOT include the
        # > "client_max_window_bits" extension parameter.

        else:
            if client_max_window_bits is not None:
                raise NegotiationError("Unexpected client_max_window_bits")

        return PerMessageDeflate(
            server_no_context_takeover,     # remote_no_context_takeover
            client_no_context_takeover,     # local_no_context_takeover
            server_max_window_bits,         # remote_max_window_bits
            client_max_window_bits,         # local_max_window_bits
        )


class ServerPerMessageDeflateFactory:
    """
    Server-side extension factory for permessage-deflate extension.

    """
    name = 'permessage-deflate'

    def __init__(
        self,
        server_no_context_takeover=False,
        client_no_context_takeover=False,
        server_max_window_bits=None,
        client_max_window_bits=None,
        **kwargs,
    ):
        """
        Configure permessage-deflate extension factory.

        See https://tools.ietf.org/html/rfc7692#section-7.1.

        """
        if not (server_max_window_bits is None or
                8 <= server_max_window_bits <= 15):
            raise ValueError("server_max_window_bits must be between 8 and 15")
        if not (client_max_window_bits is None or
                8 <= client_max_window_bits <= 15):
            raise ValueError("client_max_window_bits must be between 8 and 15")

        self.server_no_context_takeover = server_no_context_takeover
        self.client_no_context_takeover = client_no_context_takeover
        self.server_max_window_bits = server_max_window_bits
        self.client_max_window_bits = client_max_window_bits

    def process_request_params(self, params):
        """"
        Process request parameters.

        Return response params and an extension instance.

        """









        # TODO









        return (
            _build_parameters(
                server_no_context_takeover, client_no_context_takeover,
                server_max_window_bits, client_max_window_bits,
            ),
            PerMessageDeflate(
                client_no_context_takeover,     # remote_no_context_takeover
                server_no_context_takeover,     # local_no_context_takeover
                client_max_window_bits,         # remote_max_window_bits
                server_max_window_bits,         # local_max_window_bits
            )
        )


class PerMessageDeflate:
    """
    permessage-deflate extension.

    """

    def __init__(
        self,
        remote_no_context_takeover,
        local_no_context_takeover,
        remote_max_window_bits,
        local_max_window_bits,
        **kwargs,
    ):
        """
        Configure permessage-deflate extension.

        """
        self.remote_no_context_takeover = remote_no_context_takeover
        self.local_no_context_takeover = local_no_context_takeover
        self.remote_max_window_bits = remote_max_window_bits
        self.local_max_window_bits = local_max_window_bits

        if not self.remote_no_context_takeover:
            self.decoder = zlib.decompressobj(
                wbits=-self.remote_max_window_bits)

        if not self.local_no_context_takeover:
            self.encoder = zlib.compressobj(
                wbits=-self.local_max_window_bits)

        self.decode_cont_data = False
        self.encode_cont_data = False

    def decode(self, frame):
        """
        Decode an incoming frame.

        """
        # Skip control frames.
        if frame.opcode in CTRL_OPCODES:
            return frame
        # Handle continuation data frames:
        # - skip if the initial data frame wasn't encoded
        # - reset "decode continuation data" flag if it's a final frame
        elif frame.opcode == OP_CONT:
            if not self.decode_cont_data:
                return frame
            if frame.fin:
                self.decode_cont_data = False
        # Handle text and binary data frames:
        # - skip if the frame isn't encoded
        # - set "decode continuation data" flag if it's a non-final frame
        else:
            if not frame.rsv1:
                return frame
            if not frame.fin:  # frame.rsv1 is True at this point
                self.decode_cont_data = True

            # Re-initialize per-message decoder.
            if self.remote_no_context_takeover:
                self.decoder = zlib.decompressobj(
                    wbits=-self.remote_max_window_bits)

        # Uncompress compressed frames.
        data = frame.data
        if frame.fin:
            data += _EMPTY_UNCOMPRESSED_BLOCK
        data = self.decoder.decompress(data)

        return frame._replace(data=data, rsv1=False)

    def encode(self, frame):
        """
        Encode an outgoing frame.

        """
        # Skip control frames.
        if frame.opcode in CTRL_OPCODES:
            return frame

        if self.local_no_context_takeover:
            self.encoder = zlib.compressobj(
                wbits=-self.local_max_window_bits)

        # Compress data frames.
        # Since we don't do fragmentation, this is easy.
        data = (
            self.encoder.compress(frame.data) +
            self.encoder.flush(zlib.Z_SYNC_FLUSH)
        )
        if data.endswith(_EMPTY_UNCOMPRESSED_BLOCK):  # pragma: no cover
            data = data[:-4]

        return frame._replace(data=data, rsv1=frame.opcode != OP_CONT)
