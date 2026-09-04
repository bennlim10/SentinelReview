import hashlib
import pytest
from app.models import Finding
from evaluation.models import BenchmarkCase, LabelProvenance, LicenseInfo, LineRange


def make_finding(**changes):
    values=dict(severity='HIGH',confidence='HIGH',category='security',filename='case.py',
        line_number=5,description='Synthetic finding',source='bandit',rule_id='B999',cwe_id=78,
        is_on_changed_line=None)
    values.update(changes)
    return Finding(**values)


@pytest.fixture
def case_factory():
    def create(**changes):
        code=changes.pop('code','pass\n')
        values=dict(case_id='case-1',source_dataset='synthetic',source_reference='local',source_revision='1',
            language='python',filename='case.py',vulnerability_present=True,cwe_ids=['CWE-78'],
            expected_category=None,vulnerable_line_range=LineRange(start=5,end=5),
            assessment_line_range=LineRange(start=4,end=6),code=code,fixture_path=None,
            code_sha256=hashlib.sha256(code.encode()).hexdigest(),pair_id=None,
            changed_line_ranges=[LineRange(start=5,end=5)],notes='synthetic',
            label_provenance=LabelProvenance(kind='constructed_fixture',reference='local',rationale='test'),
            license=LicenseInfo(identifier=None,reference='local'))
        values.update(changes)
        return BenchmarkCase(**values)
    return create


@pytest.fixture
def finding_factory():
    return make_finding
