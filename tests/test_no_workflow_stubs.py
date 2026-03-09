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

"""P2-1 regression guard: no activity method body may contain a stub.

This test uses ``inspect.getsource()`` to assert that no
:class:`~src.control_plane.scheduler.AegisActivities` activity method body
contains ``pass``, ``...``, or ``raise NotImplementedError``.

Any stub body is a hard CI failure — it indicates an activity has not been
implemented and would silently fail at runtime when the Temporal worker attempts
to execute it.
"""

from __future__ import annotations

import inspect
import textwrap

import pytest

from src.control_plane.scheduler import AegisActivities

# ---------------------------------------------------------------------------
# The five activity methods we require to be fully implemented
# ---------------------------------------------------------------------------

_ACTIVITY_METHODS: list[tuple[str, str]] = [
    ("PrePIIScrub", "pre_pii_scrub"),
    ("PolicyEval", "policy_eval"),
    ("JITTokenIssue", "jit_token_issue"),
    ("LLMInvoke", "llm_invoke"),
    ("PostSanitize", "post_sanitize"),
]


def _get_body_lines(method: object) -> list[str]:
    """Return the non-empty, non-docstring body lines of a method.

    Strips the function signature line and leading docstring so only the
    actual implementation body is examined.
    """
    source = textwrap.dedent(inspect.getsource(method))  # type: ignore[arg-type]
    lines = source.splitlines()

    # Skip the decorator line(s) and def line.
    body_started = False
    in_docstring = False
    docstring_delimiter: str | None = None
    body_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        if not body_started:
            if stripped.startswith("def ") or stripped.startswith("async def "):
                body_started = True
            continue  # skip decorators and function signature

        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                if stripped.count('"""') >= 2 or stripped.count("'''") >= 2:
                    # Single-line docstring — skip and continue.
                    continue
                in_docstring = True
                docstring_delimiter = '"""' if '"""' in stripped else "'''"
                continue
            # Real body line.
            if stripped:
                body_lines.append(stripped)
        else:
            # Inside a multi-line docstring.
            if docstring_delimiter in stripped:
                in_docstring = False
            # Skip all docstring lines.

    return body_lines


class TestNoActivityStubs:
    """Regression guard: every AegisActivities method must have a real implementation.

    Any ``pass``, ``...``, or ``raise NotImplementedError`` in a method body is
    treated as a stub — a hard CI failure indicating the activity has not been
    implemented.
    """

    @pytest.mark.parametrize("activity_name,method_name", _ACTIVITY_METHODS)
    def test_method_body_is_not_pass(
        self, activity_name: str, method_name: str
    ) -> None:
        """Activity method body must not be a bare ``pass`` statement."""
        method = getattr(AegisActivities, method_name)
        body_lines = _get_body_lines(method)
        assert body_lines, f"AegisActivities.{method_name} has an empty body"
        for line in body_lines:
            assert line.strip() != "pass", (
                f"AegisActivities.{method_name} (activity {activity_name!r}) "
                f"contains a stub 'pass' body — implement the activity before merging"
            )

    @pytest.mark.parametrize("activity_name,method_name", _ACTIVITY_METHODS)
    def test_method_body_is_not_ellipsis(
        self, activity_name: str, method_name: str
    ) -> None:
        """Activity method body must not be a bare ``...`` expression."""
        method = getattr(AegisActivities, method_name)
        body_lines = _get_body_lines(method)
        assert body_lines, f"AegisActivities.{method_name} has an empty body"
        for line in body_lines:
            assert line.strip() != "...", (
                f"AegisActivities.{method_name} (activity {activity_name!r}) "
                f"contains a stub '...' body — implement the activity before merging"
            )

    @pytest.mark.parametrize("activity_name,method_name", _ACTIVITY_METHODS)
    def test_method_body_does_not_raise_not_implemented(
        self, activity_name: str, method_name: str
    ) -> None:
        """Activity method body must not raise ``NotImplementedError``."""
        method = getattr(AegisActivities, method_name)
        body_lines = _get_body_lines(method)
        assert body_lines, f"AegisActivities.{method_name} has an empty body"
        source = inspect.getsource(method)  # type: ignore[arg-type]
        # Strip docstrings before checking for NotImplementedError.
        # A simple check for the raise pattern in the cleaned body lines.
        not_impl_lines = [
            ln
            for ln in body_lines
            if "NotImplementedError" in ln and ln.strip().startswith("raise")
        ]
        assert not not_impl_lines, (
            f"AegisActivities.{method_name} (activity {activity_name!r}) "
            f"contains 'raise NotImplementedError' — implement the activity before merging. "
            f"Offending lines: {not_impl_lines}"
        )
        # Belt-and-suspenders: inspect the full source for unacceptable patterns.
        # We allow the string to appear in comments and docstrings only.
        non_comment_lines = [
            ln
            for ln in source.splitlines()
            if "raise NotImplementedError" in ln
            and not ln.strip().startswith("#")
            and not ln.strip().startswith(("'", '"'))
        ]
        assert not non_comment_lines, (
            f"AegisActivities.{method_name} source contains 'raise NotImplementedError' "
            f"outside comments/docstrings: {non_comment_lines}"
        )

    def test_all_five_activity_methods_are_present(self) -> None:
        """All five activity methods must exist on AegisActivities."""
        for _activity_name, method_name in _ACTIVITY_METHODS:
            assert hasattr(AegisActivities, method_name), (
                f"AegisActivities is missing method {method_name!r}"
            )

    def test_scheduler_module_imports_without_error(self) -> None:
        """src.control_plane.scheduler must import cleanly (no top-level errors)."""
        import src.control_plane.scheduler as sched  # noqa: F401

        assert sched.AgentTaskWorkflow is not None
        assert sched.AegisActivities is not None
