import hashlib
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from evaluation.models import BenchmarkCase, DatasetManifest
from evaluation.source import cache_path, retrieve


def real_case(**overrides):
    data = b"dangerous(value)\n"
    values = {
        "case_id": "pair-vulnerable", "source_dataset": "pilot",
        "source_reference": "https://github.com/advisories/GHSA-2345-6789-cfgh",
        "source_revision": "a" * 40, "language": "python", "filename": "src/file.py",
        "vulnerability_present": True, "cwe_ids": ["CWE-78"],
        "vulnerable_line_range": {"start": 1, "end": 1},
        "assessment_line_range": {"start": 1, "end": 1}, "code": None,
        "fixture_path": None, "code_sha256": hashlib.sha256(data).hexdigest(),
        "pair_id": "pair", "pair_role": "vulnerable", "benchmark_group": "real_world",
        "repository": "https://github.com/example/project", "fixing_commit": "b" * 40,
        "cve_id": "CVE-2026-0001", "ghsa_id": "GHSA-2345-6789-cfgh",
        "advisory_references": ["https://github.com/advisories/GHSA-2345-6789-cfgh"],
        "duplicate_cluster_id": "cluster", "code_fingerprint": hashlib.sha256(data).hexdigest(),
        "normalized_fingerprint": None, "selection_reason": "reviewed pilot candidate",
        "known_scanner_test_overlap": False, "changed_line_ranges": None, "notes": "",
        "label_provenance": {"kind": "reviewed_advisory_manual_localization",
            "reference": "https://github.com/advisories/GHSA-2345-6789-cfgh",
            "rationale": "reviewed advisory and localized fixing diff", "reviewed_by": "reviewer",
            "reviewer_status": "single_reviewer",
            "reviewed_at": datetime(2026, 9, 4, tzinfo=timezone.utc)},
        "license": {"identifier": "MIT", "reference": "https://example.test/LICENSE",
            "source_retrieval_mode": "immutable_reference_fetch",
            "redistribution": "retain notice"},
    }
    values.update(overrides)
    return BenchmarkCase.model_validate(values), data


class FakeClient:
    def __init__(self, data):
        self.data = data

    def get(self, url, headers):
        return httpx.Response(200, content=self.data,
                              request=httpx.Request("GET", url, headers=headers))


def test_immutable_source_retrieval_and_cache(tmp_path):
    case, data = real_case()
    assert retrieve(case, tmp_path, client=FakeClient(data)) == data
    assert cache_path(case, tmp_path).read_bytes() == data


def test_cache_path_containment_rejects_invalid_repository(tmp_path):
    case, _ = real_case(repository="https://example.com/owner/repository")
    with pytest.raises(ValueError, match="github.com"):
        cache_path(case, tmp_path)


def test_corrupted_cached_source_is_rejected(tmp_path):
    case, _ = real_case()
    target = cache_path(case, tmp_path)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="cached source hash mismatch"):
        retrieve(case, tmp_path, client=FakeClient(b"unused"))


def test_mismatched_download_is_rejected_without_caching(tmp_path):
    case, _ = real_case()
    with pytest.raises(ValueError, match="downloaded source hash mismatch"):
        retrieve(case, tmp_path, client=FakeClient(b"wrong"))
    assert not cache_path(case, tmp_path).exists()


def test_real_world_provenance_and_license_are_required():
    with pytest.raises(ValidationError, match="complete review provenance"):
        real_case(label_provenance={"kind": "reviewed_advisory_manual_localization",
            "reference": "reference", "rationale": "rationale"})
    with pytest.raises(ValidationError, match="complete license metadata"):
        real_case(license={"reference": "reference",
            "source_retrieval_mode": "immutable_reference_fetch"})


def test_pair_metadata_validation():
    vulnerable, _ = real_case()
    fixed, _ = real_case(case_id="pair-fixed", source_revision="b" * 40,
        vulnerability_present=False, vulnerable_line_range=None, pair_role="fixed")
    DatasetManifest(dataset_name="pilot", dataset_version="v1", cases=[vulnerable, fixed])
    bad_fixed = fixed.model_copy(update={"filename": "other.py"})
    with pytest.raises(ValidationError, match="pair metadata mismatch"):
        DatasetManifest(dataset_name="pilot", dataset_version="v1",
                        cases=[vulnerable, bad_fixed])


def test_pilot_manifest_has_six_valid_paired_cases():
    manifest = DatasetManifest.model_validate_json(
        Path("evaluation/benchmarks/real-world-pilot-v1/manifest.json").read_text())
    assert len(manifest.cases) == 6
    assert {case.pair_role for case in manifest.cases} == {"vulnerable", "fixed"}
