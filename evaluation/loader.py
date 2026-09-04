import hashlib
import json
from pathlib import Path

from evaluation.models import DatasetManifest


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: str | Path, *, max_fixture_bytes: int = 1_000_000,
                  cache_dir: str | Path = "evaluation/cache"):
    manifest_path = Path(path).resolve()
    raw = manifest_path.read_bytes()
    manifest = DatasetManifest.model_validate_json(raw)
    root = manifest_path.parent
    contents = {}
    hashes = {}
    for case in manifest.cases:
        if case.license.source_retrieval_mode == "immutable_reference_fetch":
            from evaluation.source import retrieve
            data = retrieve(case, cache_dir)
        elif case.code is not None:
            data = case.code.encode()
        else:
            target = (root / case.fixture_path).resolve()
            if not target.is_relative_to(root):
                raise ValueError("fixture path escapes dataset directory")
            data = target.read_bytes()
        if len(data) > max_fixture_bytes:
            raise ValueError(f"fixture exceeds size limit: {case.case_id}")
        line_count = len(data.decode("utf-8").splitlines())
        if case.assessment_line_range.end > line_count:
            raise ValueError(f"assessment scope exceeds fixture lines: {case.case_id}")
        digest = sha256(data)
        if digest != case.code_sha256:
            raise ValueError(f"fixture hash mismatch: {case.case_id}")
        if case.code_fingerprint:
            from evaluation.source import assessment_fingerprints
            exact, normalized = assessment_fingerprints(case, data)
            if exact != case.code_fingerprint:
                raise ValueError(f"assessment fingerprint mismatch: {case.case_id}")
            if case.normalized_fingerprint and normalized != case.normalized_fingerprint:
                raise ValueError(f"normalized fingerprint mismatch: {case.case_id}")
        contents[case.case_id] = data
        hashes[case.case_id] = digest
    return manifest, contents, sha256(raw), hashes
