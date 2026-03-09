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

"""Phase 2 (P2-3) tests: encrypted context persistence.

Test classes
------------
TestEncryptedPayloadCodecUnit
    Unit tests for EncryptedPayloadCodec encode/decode without a Temporal server.
    These run in every CI environment with no external dependencies.

TestRoundTripCorrectness
    Unit tests verifying byte-for-byte round-trip fidelity for all five activity
    input/output types.

TestKeyMismatchError
    Unit tests verifying that decryption with the wrong key raises DataConverterError
    and the workflow terminates without leaking plaintext.

TestPlaintextHardFailureGuard
    CI guard asserting the Aegis DataConverter is not the SDK default and has
    an EncryptedPayloadCodec attached.

TestEncryptionInTransit
    Integration tests running a full workflow and verifying workflow history
    payloads are encrypted (no plaintext prompt text found).
"""

from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import threading
import uuid
from dataclasses import asdict
from typing import Any

import pytest
from cryptography.fernet import Fernet
from temporalio import activity
from temporalio.api.common.v1 import Payload
from temporalio.client import Client
from temporalio.converter import DataConverter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from src.control_plane.data_converter import (
    _ENCRYPTED_ENCODING,
    DataConverterError,
    EncryptedPayloadCodec,
    create_aegis_data_converter,
)
from src.control_plane.scheduler import (
    AgentTaskWorkflow,
    JITTokenInput,
    JITTokenResult,
    LLMInvokeInput,
    LLMInvokeResult,
    PolicyEvalInput,
    PolicyEvalResult,
    PostSanitizeInput,
    PostSanitizeResult,
    PrePIIScrubResult,
    WorkflowInput,
)

_MP_CONTEXT = multiprocessing.get_context("spawn")


def _make_key() -> bytes:
    """Generate a fresh Fernet key for testing."""
    return Fernet.generate_key()


def _make_payload(data: bytes, encoding: bytes = b"json/plain") -> Payload:
    """Build a simple Payload for codec testing."""
    return Payload(metadata={"encoding": encoding}, data=data)


def _get_temporal_target_host(env: WorkflowEnvironment) -> str:
    """Return the Temporal dev server target host across SDK config shapes."""
    config = env.client.config()
    if isinstance(config, dict):
        target_host = config.get("target_host")
        if isinstance(target_host, str) and target_host:
            return target_host
    return env.client.service_client.config.target_host


def _schedule_worker_exit() -> None:
    """Exit shortly after returning so Temporal can persist the activity result."""
    threading.Timer(1.0, os._exit, args=(1,)).start()


# ---------------------------------------------------------------------------
# Unit tests — EncryptedPayloadCodec basics
# ---------------------------------------------------------------------------


class TestEncryptedPayloadCodecUnit:
    """P2-3 unit: EncryptedPayloadCodec encrypts outbound and decrypts inbound payloads."""

    @pytest.mark.asyncio
    async def test_encode_changes_encoding_label_to_aegis_encrypted(self) -> None:
        """Encoded payloads must carry the binary/aegis-encrypted encoding label."""
        codec = EncryptedPayloadCodec(key=_make_key())
        p = _make_payload(b'{"hello": "world"}')
        [encoded] = await codec.encode([p])
        assert encoded.metadata["encoding"] == _ENCRYPTED_ENCODING

    @pytest.mark.asyncio
    async def test_encode_data_is_not_plaintext(self) -> None:
        """Encoded payload data must not contain the original plaintext bytes."""
        codec = EncryptedPayloadCodec(key=_make_key())
        original_data = b'{"secret": "do not leak"}'
        p = _make_payload(original_data)
        [encoded] = await codec.encode([p])
        assert b"do not leak" not in encoded.data
        assert original_data not in encoded.data

    @pytest.mark.asyncio
    async def test_decode_restores_original_data(self) -> None:
        """Decoded payload must have the same data as before encoding."""
        key = _make_key()
        codec = EncryptedPayloadCodec(key=key)
        original_data = b'{"result": 42}'
        p = _make_payload(original_data)
        [encoded] = await codec.encode([p])
        [decoded] = await codec.decode([encoded])
        assert decoded.data == original_data

    @pytest.mark.asyncio
    async def test_decode_restores_original_encoding_label(self) -> None:
        """Decoded payload must restore the original encoding metadata."""
        key = _make_key()
        codec = EncryptedPayloadCodec(key=key)
        original_encoding = b"json/plain"
        p = _make_payload(b"data", encoding=original_encoding)
        [encoded] = await codec.encode([p])
        [decoded] = await codec.decode([encoded])
        assert decoded.metadata["encoding"] == original_encoding

    @pytest.mark.asyncio
    async def test_encode_is_idempotent_for_already_encrypted_payloads(self) -> None:
        """Payloads already carrying binary/aegis-encrypted must be returned unchanged."""
        key = _make_key()
        codec = EncryptedPayloadCodec(key=key)
        p = _make_payload(b"binary-blob", encoding=_ENCRYPTED_ENCODING)
        [encoded] = await codec.encode([p])
        assert encoded.data == b"binary-blob"  # unchanged

    @pytest.mark.asyncio
    async def test_decode_passes_through_non_encrypted_payloads(self) -> None:
        """Payloads without binary/aegis-encrypted encoding must be returned unchanged."""
        key = _make_key()
        codec = EncryptedPayloadCodec(key=key)
        p = _make_payload(b"plain-data", encoding=b"json/plain")
        [decoded] = await codec.decode([p])
        assert decoded.data == b"plain-data"

    @pytest.mark.asyncio
    async def test_multiple_payloads_all_encrypted(self) -> None:
        """All payloads in a batch must be encrypted independently."""
        key = _make_key()
        codec = EncryptedPayloadCodec(key=key)
        payloads = [_make_payload(f"payload-{i}".encode()) for i in range(5)]
        encoded_list = await codec.encode(payloads)
        assert len(encoded_list) == 5
        for i, enc in enumerate(encoded_list):
            assert enc.metadata["encoding"] == _ENCRYPTED_ENCODING
            assert f"payload-{i}".encode() not in enc.data


# ---------------------------------------------------------------------------
# Unit tests — round-trip correctness for all five activity I/O types
# ---------------------------------------------------------------------------


class TestRoundTripCorrectness:
    """P2-3 unit: serialize/deserialize each activity I/O type through the codec."""

    def _roundtrip(self, data: bytes, key: bytes) -> bytes:
        """Synchronously encode then decode using the given key."""
        import asyncio
        codec = EncryptedPayloadCodec(key=key)
        p = _make_payload(data)
        loop = asyncio.new_event_loop()
        try:
            [encoded] = loop.run_until_complete(codec.encode([p]))
            [decoded] = loop.run_until_complete(codec.decode([encoded]))
        finally:
            loop.close()
        return decoded.data

    def test_roundtrip_workflow_input(self) -> None:
        """WorkflowInput serialized bytes must survive a codec round-trip unchanged."""
        obj = WorkflowInput(
            task_id="tid-1",
            prompt="Hello PII: user@example.com",
            agent_type="general",
            requester_id="req-1",
        )
        data = json.dumps(asdict(obj)).encode()
        key = _make_key()
        result = self._roundtrip(data, key)
        assert result == data

    def test_roundtrip_pre_pii_scrub_result(self) -> None:
        """PrePIIScrubResult bytes must survive a codec round-trip unchanged."""
        obj = PrePIIScrubResult(
            sanitized_prompt="Hello [REDACTED-EMAIL]",
            pii_types=["email"],
        )
        data = json.dumps(asdict(obj)).encode()
        key = _make_key()
        assert self._roundtrip(data, key) == data

    def test_roundtrip_policy_eval_result(self) -> None:
        """PolicyEvalResult bytes must survive a codec round-trip unchanged."""
        obj = PolicyEvalResult(
            allowed=True,
            action="allow",
            fields=[],
            sanitized_prompt="Clean prompt",
            extra_pii_types=[],
        )
        data = json.dumps(asdict(obj)).encode()
        key = _make_key()
        assert self._roundtrip(data, key) == data

    def test_roundtrip_jit_token_result(self) -> None:
        """JITTokenResult bytes must survive a codec round-trip unchanged."""
        obj = JITTokenResult(token="eyJhbGci...", jti=str(uuid.uuid4()))
        data = json.dumps(asdict(obj)).encode()
        key = _make_key()
        assert self._roundtrip(data, key) == data

    def test_roundtrip_llm_invoke_result(self) -> None:
        """LLMInvokeResult bytes must survive a codec round-trip unchanged."""
        obj = LLMInvokeResult(
            content="The answer is 42",
            tokens_used=100,
            model="gpt-4o-mini",
            provider="openai",
        )
        data = json.dumps(asdict(obj)).encode()
        key = _make_key()
        assert self._roundtrip(data, key) == data

    def test_roundtrip_post_sanitize_result(self) -> None:
        """PostSanitizeResult bytes must survive a codec round-trip unchanged."""
        obj = PostSanitizeResult(sanitized_content="Clean response", pii_types=[])
        data = json.dumps(asdict(obj)).encode()
        key = _make_key()
        assert self._roundtrip(data, key) == data

    def test_roundtrip_is_byte_for_byte_equal(self) -> None:
        """Round-trip must produce exactly the same bytes — not just semantically equal."""
        data = b'{"x": 1, "y": [1, 2, 3], "z": "aegis"}'
        key = _make_key()
        result = self._roundtrip(data, key)
        assert result == data
        assert id(result) != id(data)  # it's a new bytes object, not the same reference


# ---------------------------------------------------------------------------
# Unit tests — key mismatch raises DataConverterError
# ---------------------------------------------------------------------------


class TestKeyMismatchError:
    """P2-3 unit: mismatched key must raise DataConverterError, never leak plaintext."""

    @pytest.mark.asyncio
    async def test_wrong_key_raises_data_converter_error(self) -> None:
        """Decrypting with a different key must raise DataConverterError."""
        encryption_key = _make_key()
        wrong_key = _make_key()
        assert encryption_key != wrong_key  # keys must differ

        encode_codec = EncryptedPayloadCodec(key=encryption_key)
        decode_codec = EncryptedPayloadCodec(key=wrong_key)

        p = _make_payload(b'{"secret": "my PII data"}')
        [encoded] = await encode_codec.encode([p])

        with pytest.raises(DataConverterError):
            await decode_codec.decode([encoded])

    @pytest.mark.asyncio
    async def test_plaintext_not_in_exception_message(self) -> None:
        """DataConverterError must not contain the original plaintext in its message."""
        encryption_key = _make_key()
        wrong_key = _make_key()

        encode_codec = EncryptedPayloadCodec(key=encryption_key)
        decode_codec = EncryptedPayloadCodec(key=wrong_key)

        secret_text = b"secret-user@example.com-ssn-123-45-6789"
        p = _make_payload(secret_text)
        [encoded] = await encode_codec.encode([p])

        try:
            await decode_codec.decode([encoded])
            pytest.fail("Expected DataConverterError was not raised")
        except DataConverterError as exc:
            # The error message must not contain any of the plaintext.
            assert b"secret" not in str(exc).encode()
            assert b"user@example.com" not in str(exc).encode()

    @pytest.mark.asyncio
    async def test_corrupted_data_raises_data_converter_error(self) -> None:
        """Corrupted encrypted data must raise DataConverterError, not raw exceptions."""
        codec = EncryptedPayloadCodec(key=_make_key())
        corrupted = _make_payload(b"not-valid-fernet-token", encoding=_ENCRYPTED_ENCODING)

        with pytest.raises(DataConverterError):
            await codec.decode([corrupted])


# ---------------------------------------------------------------------------
# Negative / CI guard — plaintext hard failure guard
# ---------------------------------------------------------------------------


class TestPlaintextHardFailureGuard:
    """P2-3 negative: Aegis DataConverter must not be the SDK default."""

    def test_create_aegis_data_converter_has_encrypted_payload_codec(self) -> None:
        """create_aegis_data_converter() must return a converter with EncryptedPayloadCodec."""
        converter = create_aegis_data_converter()
        assert isinstance(converter, DataConverter), (
            "create_aegis_data_converter() must return a DataConverter"
        )
        assert converter.payload_codec is not None, (
            "AegisDataConverter must have a non-None payload_codec — "
            "the default JsonPlainPayloadConverter must never be used"
        )
        assert isinstance(converter.payload_codec, EncryptedPayloadCodec), (
            "AegisDataConverter.payload_codec must be an EncryptedPayloadCodec, "
            "not the SDK default"
        )

    def test_aegis_converter_is_not_sdk_default(self) -> None:
        """The Aegis DataConverter must differ from DataConverter() (the SDK default)."""
        aegis = create_aegis_data_converter()
        sdk_default = DataConverter()
        assert aegis.payload_codec != sdk_default.payload_codec, (
            "Aegis DataConverter must not match the SDK default DataConverter"
        )

    def test_sdk_default_has_no_payload_codec(self) -> None:
        """The SDK default DataConverter must have no payload_codec (our baseline check)."""
        sdk_default = DataConverter()
        assert sdk_default.payload_codec is None, (
            "SDK default DataConverter.payload_codec should be None — "
            "our guard checks that aegis has a non-None codec"
        )

    def test_encrypted_payload_codec_key_is_not_empty(self) -> None:
        """EncryptedPayloadCodec must have a non-empty key."""
        key = _make_key()
        codec = EncryptedPayloadCodec(key=key)
        assert codec.key == key
        assert len(codec.key) > 0

    def test_default_dev_key_is_used_when_no_key_provided(self) -> None:
        """When no key is provided, the codec must still function (uses dev key)."""
        # This verifies the codec doesn't crash without explicit key configuration.
        codec = EncryptedPayloadCodec()
        assert codec.key is not None
        assert len(codec.key) > 0


# ---------------------------------------------------------------------------
# Integration tests — encryption in transit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEncryptionInTransit:
    """P2-3 integration: workflow history must not contain plaintext prompt text."""

    @pytest.mark.asyncio
    async def test_workflow_history_payloads_are_encrypted(self) -> None:
        """Workflow history ActivityTaskScheduled payloads must not contain plaintext input."""
        encryption_key = _make_key()
        data_converter = create_aegis_data_converter(key=encryption_key)
        secret_prompt = "AEGIS_SECRET_PROMPT_MARKER_XYZ"

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            return PolicyEvalResult(
                allowed=True, action="allow", fields=[],
                sanitized_prompt=inp.sanitized_prompt, extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm(inp: LLMInvokeInput) -> LLMInvokeResult:
            return LLMInvokeResult(
                content="Encrypted response",
                tokens_used=10,
                model="gpt-4o-mini",
                provider="openai",
            )

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        workflow_id = f"enc-transit-{uuid.uuid4()}"
        inp = WorkflowInput(
            task_id=str(uuid.uuid4()),
            prompt=secret_prompt,
            agent_type="general",
            requester_id="test-enc",
        )

        async with await WorkflowEnvironment.start_time_skipping() as env:
            client = await type(env.client).connect(
                _get_temporal_target_host(env),
                data_converter=data_converter,
            )
            async with Worker(
                client,
                task_queue="enc-transit-test",
                workflows=[AgentTaskWorkflow],
                activities=[mock_pre, mock_policy, mock_jit, mock_llm, mock_post],
            ):
                await client.execute_workflow(
                    AgentTaskWorkflow.run,
                    inp,
                    id=workflow_id,
                    task_queue="enc-transit-test",
                )

            # Retrieve workflow history and check for plaintext.
            history = await client.get_workflow_handle(workflow_id).fetch_history()

        # Serialize and scan history events for the plaintext marker.
        history_bytes = history.to_json().encode()
        assert secret_prompt.encode() not in history_bytes, (
            "Plaintext prompt found in serialized workflow history — "
            "encrypted data converter is not working"
        )


def _run_encrypted_restart_worker(
    target_host: str,
    encryption_key: bytes,
    die_after_stage: str | None,
    completion_counts: dict[str, int],
    ready_event: Any,
    stage_done_events: dict[str, Any],
    resumed_jit_inputs: Any,
) -> None:
    """Run a Temporal worker with encrypted payloads and optional staged self-termination."""

    async def _main() -> None:
        data_converter = create_aegis_data_converter(key=encryption_key)
        client = await Client.connect(target_host, data_converter=data_converter)
        crash_before_next_stage = False

        @activity.defn(name="PrePIIScrub")
        async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
            completion_counts["PrePIIScrub"] = completion_counts.get("PrePIIScrub", 0) + 1
            stage_done_events["PrePIIScrub"].set()
            if die_after_stage == "PrePIIScrub":
                _schedule_worker_exit()
            return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

        @activity.defn(name="PolicyEval")
        async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
            nonlocal crash_before_next_stage
            completion_counts["PolicyEval"] = completion_counts.get("PolicyEval", 0) + 1
            stage_done_events["PolicyEval"].set()
            if die_after_stage == "PolicyEval":
                crash_before_next_stage = True
            return PolicyEvalResult(
                allowed=True,
                action="allow",
                fields=[],
                sanitized_prompt=inp.sanitized_prompt,
                extra_pii_types=[],
            )

        @activity.defn(name="JITTokenIssue")
        async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
            if crash_before_next_stage:
                os._exit(1)
            completion_counts["JITTokenIssue"] = completion_counts.get("JITTokenIssue", 0) + 1
            resumed_jit_inputs.append(
                {
                    "task_id": inp.task_id,
                    "agent_type": inp.agent_type,
                    "requester_id": inp.requester_id,
                    "session_id": inp.session_id,
                    "rotation_key": inp.rotation_key,
                }
            )
            stage_done_events["JITTokenIssue"].set()
            if die_after_stage == "JITTokenIssue":
                _schedule_worker_exit()
            return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

        @activity.defn(name="LLMInvoke")
        async def mock_llm(inp: LLMInvokeInput) -> LLMInvokeResult:
            completion_counts["LLMInvoke"] = completion_counts.get("LLMInvoke", 0) + 1
            stage_done_events["LLMInvoke"].set()
            if die_after_stage == "LLMInvoke":
                _schedule_worker_exit()
            return LLMInvokeResult(
                content="Encrypted restart response",
                tokens_used=11,
                model="gpt-4o-mini",
                provider="openai",
            )

        @activity.defn(name="PostSanitize")
        async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
            completion_counts["PostSanitize"] = completion_counts.get("PostSanitize", 0) + 1
            stage_done_events["PostSanitize"].set()
            return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

        ready_event.set()
        async with Worker(
            client,
            task_queue="enc-restart-test",
            workflows=[AgentTaskWorkflow],
            activities=[mock_pre, mock_policy, mock_jit, mock_llm, mock_post],
        ):
            await asyncio.sleep(60)

    asyncio.run(_main())


@pytest.mark.integration
class TestEncryptedRestartContext:
    """P2-3 integration: encrypted context survives a worker restart.

    The restart must not re-run the first two activities.
    """

    @pytest.mark.asyncio
    async def test_context_available_across_restart_without_reexecuting_first_two_stages(
        self,
    ) -> None:
        encryption_key = _make_key()

        async with await WorkflowEnvironment.start_time_skipping() as env:
            target_host = _get_temporal_target_host(env)
            data_converter = create_aegis_data_converter(key=encryption_key)
            client = await Client.connect(target_host, data_converter=data_converter)

            counts1: dict[str, int] = {}
            counts2: dict[str, int] = {}
            jit_inputs1: list[dict[str, str | None]] = []
            jit_inputs2: list[dict[str, str | None]] = []
            policy_done = asyncio.Event()

            def build_activities(
                counts: dict[str, int],
                jit_inputs: list[dict[str, str | None]],
                *,
                signal_policy_done: bool = False,
            ) -> list[Any]:
                @activity.defn(name="PrePIIScrub")
                async def mock_pre(inp: WorkflowInput) -> PrePIIScrubResult:
                    counts["PrePIIScrub"] = counts.get("PrePIIScrub", 0) + 1
                    return PrePIIScrubResult(sanitized_prompt=inp.prompt, pii_types=[])

                @activity.defn(name="PolicyEval")
                async def mock_policy(inp: PolicyEvalInput) -> PolicyEvalResult:
                    counts["PolicyEval"] = counts.get("PolicyEval", 0) + 1
                    if signal_policy_done:
                        policy_done.set()
                    return PolicyEvalResult(
                        allowed=True,
                        action="allow",
                        fields=[],
                        sanitized_prompt=inp.sanitized_prompt,
                        extra_pii_types=[],
                    )

                @activity.defn(name="JITTokenIssue")
                async def mock_jit(inp: JITTokenInput) -> JITTokenResult:
                    counts["JITTokenIssue"] = counts.get("JITTokenIssue", 0) + 1
                    jit_inputs.append(
                        {
                            "task_id": inp.task_id,
                            "agent_type": inp.agent_type,
                            "requester_id": inp.requester_id,
                            "session_id": inp.session_id,
                            "rotation_key": inp.rotation_key,
                        }
                    )
                    return JITTokenResult(token="tok", jti=str(uuid.uuid4()))

                @activity.defn(name="LLMInvoke")
                async def mock_llm(inp: LLMInvokeInput) -> LLMInvokeResult:
                    counts["LLMInvoke"] = counts.get("LLMInvoke", 0) + 1
                    return LLMInvokeResult(
                        content="Encrypted restart response",
                        tokens_used=11,
                        model="gpt-4o-mini",
                        provider="openai",
                    )

                @activity.defn(name="PostSanitize")
                async def mock_post(inp: PostSanitizeInput) -> PostSanitizeResult:
                    counts["PostSanitize"] = counts.get("PostSanitize", 0) + 1
                    return PostSanitizeResult(sanitized_content=inp.content, pii_types=[])

                return [mock_pre, mock_policy, mock_jit, mock_llm, mock_post]

            workflow_input = WorkflowInput(
                task_id=str(uuid.uuid4()),
                prompt="Encrypted restart marker",
                agent_type="general",
                requester_id="enc-restart-user",
                session_id="enc-session-1",
            )

            worker1 = Worker(
                client,
                task_queue="enc-restart-test",
                workflows=[AgentTaskWorkflow],
                activities=build_activities(counts1, jit_inputs1, signal_policy_done=True),
            )
            await worker1.__aenter__()
            try:
                handle = await client.start_workflow(
                    AgentTaskWorkflow.run,
                    workflow_input,
                    id=f"enc-restart-{uuid.uuid4()}",
                    task_queue="enc-restart-test",
                )

                await asyncio.wait_for(policy_done.wait(), timeout=30.0)
                await asyncio.sleep(0.5)
            finally:
                await worker1.__aexit__(None, None, None)

            worker2 = Worker(
                client,
                task_queue="enc-restart-test",
                workflows=[AgentTaskWorkflow],
                activities=build_activities(counts2, jit_inputs2),
            )
            await worker2.__aenter__()
            try:
                result = await asyncio.wait_for(handle.result(), timeout=30.0)
            finally:
                await worker2.__aexit__(None, None, None)

            total_pre = counts1.get("PrePIIScrub", 0) + counts2.get("PrePIIScrub", 0)
            total_policy = counts1.get("PolicyEval", 0) + counts2.get("PolicyEval", 0)
            total_jit = counts1.get("JITTokenIssue", 0) + counts2.get("JITTokenIssue", 0)
            resumed_jit_payloads = jit_inputs1 + jit_inputs2

        assert result.workflow_status == "completed"
        assert total_pre == 1, f"PrePIIScrub re-executed across restart; got {total_pre}"
        assert total_policy == 1, f"PolicyEval re-executed across restart; got {total_policy}"
        assert total_jit == 1, f"JITTokenIssue should execute once after restart; got {total_jit}"

        assert resumed_jit_payloads, "Expected a preserved JITTokenIssue input payload"
        resumed_jit = resumed_jit_payloads[0]
        assert resumed_jit["task_id"] == workflow_input.task_id
        assert resumed_jit["agent_type"] == workflow_input.agent_type
        assert resumed_jit["requester_id"] == workflow_input.requester_id
        assert resumed_jit["session_id"] == workflow_input.session_id
        assert resumed_jit["rotation_key"] == f"llm:{workflow_input.task_id}"
