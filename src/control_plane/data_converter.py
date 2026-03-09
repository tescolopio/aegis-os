# Copyright 2026 Tim Escolopio / 3D Tech Solutions
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Encrypted Temporal data converter for Phase 2 (P2-3).

Ensures that agent context and intermediate workflow state are persisted in an
encrypted form in Temporal history.  Plaintext payloads in workflow history are
a hard security violation — this module enforces encryption at the codec layer.

The :class:`EncryptedPayloadCodec` implements the ``PayloadCodec`` interface from
the Temporal Python SDK.  It wraps every outbound payload's ``data`` field with
symmetric Fernet encryption before it reaches the Temporal server, and
transparently decrypts it on the way back to worker code.

Key management:
    The encryption key is sourced from the ``AEGIS_TEMPORAL_ENCRYPTION_KEY``
    environment variable (via :class:`~src.config.Settings`).  In development,
    a default key is generated deterministically so tests run without external
    configuration.  In production, this variable must be set to a
    URL-safe base64-encoded 32-byte Fernet key.

Usage::

    from src.control_plane.data_converter import create_aegis_data_converter

    client = await Client.connect(
        "localhost:7233",
        data_converter=create_aegis_data_converter(),
    )
"""

from __future__ import annotations

import base64
import os
from collections.abc import Sequence

from cryptography.fernet import Fernet, InvalidToken
from temporalio.api.common.v1 import Payload
from temporalio.converter import DataConverter, PayloadCodec

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Encoding label written into ``Payload.metadata["encoding"]`` for payloads
#: that have been encrypted by :class:`EncryptedPayloadCodec`.
_ENCRYPTED_ENCODING: bytes = b"binary/aegis-encrypted"

#: Key used for ``original-encoding`` metadata so the codec can restore the
#: original encoding label on decryption.  Must be a ``str`` because
#: ``Payload.metadata`` is a ``map<string, bytes>`` in protobuf.
_ORIGINAL_ENCODING_KEY: str = "aegis/original-encoding"

#: Development-only Fernet key.  This is a valid URL-safe base64 32-byte key
#: used **only** when ``AEGIS_TEMPORAL_ENCRYPTION_KEY`` is not set.  It must
#: never be used in production.
_DEV_KEY: bytes = base64.urlsafe_b64encode(b"aegis-dev-only-32byte-key-x12345")


class DataConverterError(RuntimeError):
    """Raised when an encrypted payload cannot be decrypted.

    This is raised when the decryption key does not match the encryption key
    (e.g., a key rotation or a test with a mismatched key).  The workflow
    terminates immediately and no plaintext is leaked.
    """


class EncryptedPayloadCodec(PayloadCodec):
    """Temporal :class:`~temporalio.converter.PayloadCodec` that encrypts all payloads.

    Every payload written to Temporal history is transparently encrypted using
    `Fernet symmetric encryption`_.  Payloads already carrying the
    ``binary/aegis-encrypted`` encoding label are skipped (idempotent encode).

    Raises:
        DataConverterError: On decode when the payload cannot be decrypted
            with the current key — indicating a key mismatch.

    .. _Fernet symmetric encryption:
        https://cryptography.io/en/latest/fernet/
    """

    def __init__(self, key: bytes | str | None = None) -> None:
        """Initialise the codec with a Fernet encryption key.

        Args:
            key: URL-safe base64-encoded 32-byte Fernet key.  When *None*, the
                key is loaded from the ``AEGIS_TEMPORAL_ENCRYPTION_KEY``
                environment variable.  When that variable is also absent, the
                compile-time development key is used.  The development key must
                never be deployed to production.

        Raises:
            ValueError: If the supplied key is not valid for Fernet.
        """
        if key is None:
            raw = os.environ.get("AEGIS_TEMPORAL_ENCRYPTION_KEY", "")
            key = raw.encode() if raw else _DEV_KEY
        elif isinstance(key, str):
            key = key.encode()
        self._fernet = Fernet(key)
        self._key: bytes = key

    @property
    def key(self) -> bytes:
        """Return the raw Fernet key bytes."""
        return self._key

    async def encode(self, payloads: Sequence[Payload]) -> list[Payload]:
        """Encrypt each payload's ``data`` field before writing to Temporal history.

        Payloads that already carry the ``binary/aegis-encrypted`` encoding label
        are returned unchanged to avoid double-encryption.

        Args:
            payloads: Sequence of :class:`~temporalio.api.common.v1.Payload`
                objects to encrypt.

        Returns:
            A new list of :class:`~temporalio.api.common.v1.Payload` objects
            where each ``data`` field is Fernet-encrypted and the ``encoding``
            metadata is set to ``binary/aegis-encrypted``.
        """
        result: list[Payload] = []
        for p in payloads:
            # Skip payloads that are already encrypted.
            if p.metadata.get("encoding") == _ENCRYPTED_ENCODING:
                result.append(p)
                continue
            original_encoding = p.metadata.get("encoding", b"json/plain")
            encrypted_data = self._fernet.encrypt(p.data)
            result.append(
                Payload(
                    metadata={
                        "encoding": _ENCRYPTED_ENCODING,
                        _ORIGINAL_ENCODING_KEY: original_encoding,
                    },
                    data=encrypted_data,
                )
            )
        return result

    async def decode(self, payloads: Sequence[Payload]) -> list[Payload]:
        """Decrypt each payload's ``data`` field on retrieval from Temporal history.

        Payloads that do not carry the ``binary/aegis-encrypted`` encoding label
        are returned unchanged to allow mixed environments during key rotation.

        Args:
            payloads: Sequence of :class:`~temporalio.api.common.v1.Payload`
                objects to decrypt.

        Returns:
            A new list of :class:`~temporalio.api.common.v1.Payload` objects
            with decrypted ``data`` and the original encoding metadata restored.

        Raises:
            DataConverterError: If decryption fails due to a key mismatch or
                payload corruption.
        """
        result: list[Payload] = []
        for p in payloads:
            if p.metadata.get("encoding") != _ENCRYPTED_ENCODING:
                result.append(p)
                continue
            try:
                decrypted_data = self._fernet.decrypt(p.data)
            except InvalidToken as exc:
                raise DataConverterError(
                    "Failed to decrypt Temporal payload: key mismatch or corrupted data. "
                    "Verify AEGIS_TEMPORAL_ENCRYPTION_KEY is consistent across all workers."
                ) from exc
            original_encoding = p.metadata.get(_ORIGINAL_ENCODING_KEY, b"json/plain")
            result.append(
                Payload(
                    metadata={"encoding": original_encoding},
                    data=decrypted_data,
                )
            )
        return result


def create_aegis_data_converter(key: bytes | str | None = None) -> DataConverter:
    """Create a :class:`~temporalio.converter.DataConverter` with Aegis-encrypted payloads.

    This is the factory function that should be passed to both
    ``temporalio.client.Client.connect()`` and
    ``temporalio.worker.Worker()`` to ensure all workflow state is encrypted in
    transit and at rest in Temporal history.

    The returned converter uses the default JSON payload converter for
    serialisation/deserialisation, with the :class:`EncryptedPayloadCodec` applied
    as a post-processing codec to encrypt the serialised bytes.

    Args:
        key: Optional Fernet key override.  When *None*, sourced from
            ``AEGIS_TEMPORAL_ENCRYPTION_KEY``.  See :class:`EncryptedPayloadCodec`
            for full key-resolution semantics.

    Returns:
        A configured :class:`~temporalio.converter.DataConverter` instance.
    """
    return DataConverter(payload_codec=EncryptedPayloadCodec(key=key))
