import pytest
from evaluation.metrics import binary_metrics,ratio
from evaluation.models import TargetResult


def result(status): return TargetResult(case_id=status,mode='bandit',status=status,
 detected=None,findings=[],unadjudicated_findings=[],scanner_errors=[],runtime_seconds=0,
 changed_line_status=status)

def test_binary_metrics():
 m=binary_metrics([result(x) for x in ['tp','tp','fp','tn','fn','unscorable','scanner_error']])
 assert (m.true_positives,m.false_positives,m.true_negatives,m.false_negatives)==(2,1,1,1)
 assert m.precision==pytest.approx(2/3) and m.recall==pytest.approx(2/3)
 assert m.false_positive_rate==.5 and m.f1==pytest.approx(2/3)
 assert m.unscorable==1 and m.scanner_errors==1

def test_zero_denominators():
 m=binary_metrics([])
 assert m.precision is None and m.recall is None and m.false_positive_rate is None and m.f1 is None
 assert ratio(0,0) is None
