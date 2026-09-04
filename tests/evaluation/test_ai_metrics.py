from app.ai.models import AIReview,ReviewOutput
from evaluation.ai_metrics import evaluate_ai
from evaluation.models import FindingRecord,TargetResult


def review(verdict='needs_review',priority='medium',confidence=.5,status='completed'):
 output=ReviewOutput(verdict=verdict,exploitability='unknown',impact='unknown',priority=priority,
  confidence=confidence,reasoning='synthetic',remediation='synthetic',evidence_used=['scanner:0']) if status=='completed' else None
 return AIReview(status=status,selected=True,result=output)
def target(status,review):
 record=FindingRecord(source='bandit',sources=['bandit'],filename='x.py',line_number=1,rule_id='B1',rule_ids=['B1'],cwe_ids=['CWE-1'],
  severity='HIGH',in_assessment_scope=True,target_match=True,changed_line=None,ai_review=review)
 return TargetResult(case_id=status,mode='combined',status=status,detected=True,findings=[record],
  unadjudicated_findings=[],scanner_errors=[],runtime_seconds=0)

def test_ai_verdicts_and_abstention():
 m=evaluate_ai([target('tp',review('likely_valid','high',.9)),target('fp',review('likely_false_positive','low',.8)),
  target('tp',review()),target('tp',review(status='failed'))])
 assert m.available_reviews==3 and m.unavailable_reviews==1 and m.decisive_reviews==2 and m.needs_review==1
 assert m.likely_valid_correct==1 and m.likely_false_positive_correct==1
 assert m.priority_distribution=={'high':1,'low':1,'medium':1}

def test_ai_disagreement_risk():
 m=evaluate_ai([target('tp',review('likely_false_positive','low',.7)),target('fp',review('likely_valid','high',.6))])
 assert m.likely_false_positive_incorrect==1 and m.likely_valid_incorrect==1
 assert m.true_finding_downrank_risk==1 and m.confidence_incorrect==[.7,.6]

def test_noncombined_not_double_counted():
 item=target('tp',review('likely_valid'));item.mode='bandit'
 assert evaluate_ai([item]).available_reviews==0
