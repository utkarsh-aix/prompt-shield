"""
test_context_validator.py — Tests for ContextValidator (Phase 2.4).

Test groups
-----------
TestSafeChunks             — Verification when all chunks are safe.
TestUnsafeChunks           — Verification when one or more chunks are unsafe.
TestMixedChunks            — Mixed safe/unsafe chunk verification.
TestSuspiciousChunkActions — How suspicious chunks behave under allow/warn/remove.
TestStrictValidation       — Behavior of the validator under strict=True.
TestEdgeCases              — Empty list inputs, incorrect argument types, invalid configs.
TestSerialization          — to_dict() serialization accuracy.
"""

import pytest

from prompt_shield.chunk_scanner import ChunkScanResult
from prompt_shield.context_validator import ContextValidationResult, ContextValidator


def make_chunk_res(chunk_id: int, text: str, score: int) -> ChunkScanResult:
    """Helper to construct dummy ChunkScanResult objects for validation tests."""
    return ChunkScanResult(
        chunk_id=chunk_id,
        chunk_text=text,
        risk_score=score,
        safe=(score < 30),
        threats=[],
    )


# ---------------------------------------------------------------------------
# Safe chunks
# ---------------------------------------------------------------------------


class TestSafeChunks:
    """Validator behavior when all input chunks are safe."""

    def test_all_safe_chunks(self) -> None:
        validator = ContextValidator()
        chunks = [
            make_chunk_res(0, "Safe chunk one", 0),
            make_chunk_res(1, "Safe chunk two", 15),
            make_chunk_res(2, "Safe chunk three", 29),
        ]

        # Test filter_chunks
        filtered = validator.filter_chunks(chunks)
        assert len(filtered) == 3
        assert [c.chunk_id for c in filtered] == [0, 1, 2]

        # Test validate_chunks
        res = validator.validate_chunks(chunks)
        assert isinstance(res, ContextValidationResult)
        assert res.total_chunks == 3
        assert len(res.safe_chunks) == 3
        assert len(res.unsafe_chunks) == 0
        assert len(res.filtered_chunks) == 0
        assert res.validation_passed is True

        # Test summarize_validation
        summary = validator.summarize_validation(res)
        assert summary["total_chunks"] == 3
        assert summary["safe_chunks"] == 3
        assert summary["filtered_chunks"] == 0
        assert summary["highest_risk_score"] == 29
        assert summary["validation_passed"] is True


# ---------------------------------------------------------------------------
# Unsafe chunks
# ---------------------------------------------------------------------------


class TestUnsafeChunks:
    """Validator behavior when chunks are unsafe (score >= 70)."""

    def test_one_unsafe_chunk(self) -> None:
        validator = ContextValidator()
        chunks = [
            make_chunk_res(0, "Unsafe chunk", 95),
        ]

        # Test filter_chunks
        filtered = validator.filter_chunks(chunks)
        assert len(filtered) == 0

        # Test validate_chunks
        res = validator.validate_chunks(chunks)
        assert res.total_chunks == 1
        assert len(res.safe_chunks) == 0
        assert len(res.unsafe_chunks) == 1
        assert len(res.filtered_chunks) == 1
        assert res.unsafe_chunks[0].chunk_id == 0
        assert res.validation_passed is True  # Non-strict mode passes validation

        # Test summarize_validation
        summary = validator.summarize_validation(res)
        assert summary["total_chunks"] == 1
        assert summary["safe_chunks"] == 0
        assert summary["filtered_chunks"] == 1
        assert summary["highest_risk_score"] == 95
        assert summary["validation_passed"] is True

    def test_multiple_unsafe_chunks(self) -> None:
        validator = ContextValidator()
        chunks = [
            make_chunk_res(0, "Unsafe chunk one", 70),
            make_chunk_res(1, "Unsafe chunk two", 80),
        ]

        # Test filter_chunks
        filtered = validator.filter_chunks(chunks)
        assert len(filtered) == 0

        # Test validate_chunks
        res = validator.validate_chunks(chunks)
        assert res.total_chunks == 2
        assert len(res.safe_chunks) == 0
        assert len(res.unsafe_chunks) == 2
        assert len(res.filtered_chunks) == 2
        assert res.validation_passed is True

        summary = validator.summarize_validation(res)
        assert summary["filtered_chunks"] == 2
        assert summary["highest_risk_score"] == 80


# ---------------------------------------------------------------------------
# Mixed chunks
# ---------------------------------------------------------------------------


class TestMixedChunks:
    """Validator behavior with a mix of safe and unsafe chunks."""

    def test_mixed_safe_and_unsafe(self) -> None:
        validator = ContextValidator()
        chunks = [
            make_chunk_res(0, "Safe context paragraph", 10),
            make_chunk_res(1, "Unsafe injection instructions", 90),
            make_chunk_res(2, "Another safe context paragraph", 0),
        ]

        # Test filter_chunks
        filtered = validator.filter_chunks(chunks)
        assert len(filtered) == 2
        assert [c.chunk_id for c in filtered] == [0, 2]

        # Test validate_chunks
        res = validator.validate_chunks(chunks)
        assert res.total_chunks == 3
        assert len(res.safe_chunks) == 2
        assert [c.chunk_id for c in res.safe_chunks] == [0, 2]
        assert len(res.unsafe_chunks) == 1
        assert res.unsafe_chunks[0].chunk_id == 1
        assert len(res.filtered_chunks) == 1
        assert res.filtered_chunks[0].chunk_id == 1
        assert res.validation_passed is True

        summary = validator.summarize_validation(res)
        assert summary["total_chunks"] == 3
        assert summary["safe_chunks"] == 2
        assert summary["filtered_chunks"] == 1
        assert summary["highest_risk_score"] == 90
        assert summary["validation_passed"] is True


# ---------------------------------------------------------------------------
# Suspicious actions handling
# ---------------------------------------------------------------------------


class TestSuspiciousChunkActions:
    """Configurable handling of suspicious chunks (score 30-69)."""

    @pytest.fixture()
    def suspicious_chunks(self) -> list[ChunkScanResult]:
        return [
            make_chunk_res(0, "Safe chunk", 10),
            make_chunk_res(1, "Suspicious chunk", 50),
            make_chunk_res(2, "Unsafe chunk", 80),
        ]

    def test_action_allow(self, suspicious_chunks: list[ChunkScanResult]) -> None:
        validator = ContextValidator(suspicious_action="allow")
        res = validator.validate_chunks(suspicious_chunks)

        # Suspicious chunk should be allowed (total safe chunks = 2)
        assert len(res.safe_chunks) == 2
        assert [c.chunk_id for c in res.safe_chunks] == [0, 1]
        assert len(res.filtered_chunks) == 1
        assert res.filtered_chunks[0].chunk_id == 2  # Only unsafe is filtered

    def test_action_warn(
        self, suspicious_chunks: list[ChunkScanResult], caplog: pytest.LogCaptureFixture
    ) -> None:
        validator = ContextValidator(suspicious_action="warn")
        res = validator.validate_chunks(suspicious_chunks)

        # Suspicious chunk should be allowed (same as allow)
        assert len(res.safe_chunks) == 2
        assert [c.chunk_id for c in res.safe_chunks] == [0, 1]
        assert len(res.filtered_chunks) == 1

        # Check that warning was logged
        warnings = [
            record.message for record in caplog.records if record.levelname == "WARNING"
        ]
        assert len(warnings) > 0
        assert "Suspicious chunk allowed with warning" in warnings[0]

    def test_action_remove(self, suspicious_chunks: list[ChunkScanResult]) -> None:
        validator = ContextValidator(suspicious_action="remove")
        res = validator.validate_chunks(suspicious_chunks)

        # Suspicious chunk should be removed/filtered (total safe chunks = 1)
        assert len(res.safe_chunks) == 1
        assert res.safe_chunks[0].chunk_id == 0
        assert len(res.filtered_chunks) == 2
        assert {c.chunk_id for c in res.filtered_chunks} == {1, 2}


# ---------------------------------------------------------------------------
# Strict validation mode
# ---------------------------------------------------------------------------


class TestStrictValidation:
    """Validation behavior when strict=True."""

    def test_strict_passes_on_pure_safe(self) -> None:
        validator = ContextValidator(strict=True)
        chunks = [
            make_chunk_res(0, "Safe chunk", 10),
        ]
        res = validator.validate_chunks(chunks)
        assert res.validation_passed is True

    def test_strict_fails_on_unsafe(self) -> None:
        validator = ContextValidator(strict=True)
        chunks = [
            make_chunk_res(0, "Safe chunk", 10),
            make_chunk_res(1, "Unsafe chunk", 75),
        ]
        res = validator.validate_chunks(chunks)
        assert res.validation_passed is False

    def test_strict_fails_on_removed_suspicious(self) -> None:
        # If suspicious is removed, it is filtered, so strict mode fails validation
        validator = ContextValidator(suspicious_action="remove", strict=True)
        chunks = [
            make_chunk_res(0, "Safe chunk", 10),
            make_chunk_res(1, "Suspicious chunk", 45),
        ]
        res = validator.validate_chunks(chunks)
        assert res.validation_passed is False

    def test_strict_passes_on_allowed_suspicious(self) -> None:
        # If suspicious is allowed, it is not filtered, so strict mode passes validation
        validator = ContextValidator(suspicious_action="allow", strict=True)
        chunks = [
            make_chunk_res(0, "Safe chunk", 10),
            make_chunk_res(1, "Suspicious chunk", 45),
        ]
        res = validator.validate_chunks(chunks)
        assert res.validation_passed is True


# ---------------------------------------------------------------------------
# Edge Cases and Parameters
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Parameter boundaries and invalid configurations."""

    def test_empty_input_list(self) -> None:
        validator = ContextValidator()
        filtered = validator.filter_chunks([])
        assert filtered == []

        res = validator.validate_chunks([])
        assert res.total_chunks == 0
        assert res.safe_chunks == []
        assert res.unsafe_chunks == []
        assert res.filtered_chunks == []
        assert res.validation_passed is True

        summary = validator.summarize_validation(res)
        assert summary["total_chunks"] == 0
        assert summary["highest_risk_score"] == 0

    def test_invalid_constructor_args(self) -> None:
        with pytest.raises(ValueError):
            ContextValidator(suspicious_action="invalid_action")

    def test_invalid_type_filter_chunks(self) -> None:
        validator = ContextValidator()
        with pytest.raises(TypeError):
            validator.filter_chunks(1234)  # type: ignore[arg-type]

    def test_invalid_type_validate_chunks(self) -> None:
        validator = ContextValidator()
        with pytest.raises(TypeError):
            validator.validate_chunks(None)  # type: ignore[arg-type]

    def test_invalid_items_in_list(self) -> None:
        validator = ContextValidator()
        with pytest.raises(TypeError):
            validator.filter_chunks(["string_instead_of_result"])  # type: ignore[list-item]

        with pytest.raises(TypeError):
            validator.validate_chunks([12345])  # type: ignore[list-item]

    def test_invalid_summary_arg(self) -> None:
        validator = ContextValidator()
        with pytest.raises(TypeError):
            validator.summarize_validation("invalid_result_type")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


class TestSerialization:
    """Serialization outputs are formatted correctly."""

    def test_to_dict_keys_and_values(self) -> None:
        validator = ContextValidator(suspicious_action="remove")
        chunks = [
            make_chunk_res(0, "Safe chunk", 10),
            make_chunk_res(1, "Suspicious chunk", 40),
            make_chunk_res(2, "Unsafe chunk", 80),
        ]
        res = validator.validate_chunks(chunks)
        d = res.to_dict()

        assert isinstance(d, dict)
        assert d["total_chunks"] == 3
        assert d["validation_passed"] is True

        # Check list sizes in dict
        assert len(d["safe_chunks"]) == 1
        assert len(d["unsafe_chunks"]) == 1
        assert len(d["filtered_chunks"]) == 2

        # Check structure of items in lists
        assert d["safe_chunks"][0]["chunk_id"] == 0
        assert d["unsafe_chunks"][0]["chunk_id"] == 2
