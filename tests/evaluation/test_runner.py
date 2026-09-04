from pathlib import Path
import subprocess
import pytest
from app.models import Finding,ScannerError
from app.scanners.base import ScannerResult
from evaluation.runner import EvaluationConfig,run_evaluation,validate_semgrep_config

MANIFEST=Path('evaluation/fixtures/manifest.json')
RULES=Path('evaluation/fixtures/semgrep/synthetic-security.yaml')

def finding(source,filename,line,rule,cwe):
 return Finding(severity='HIGH',confidence='HIGH' if source=='bandit' else None,category='security',
  filename=filename,line_number=line,description='synthetic',source=source,rule_id=rule,cwe_id=cwe,
  is_on_changed_line=None)

def fake_scan(scanner, failures=None):
 failures=failures or set()
 def scan(files,timeout,**kwargs):
  name=next(iter(files));case=name.split('.')[0]
  if case in failures:
   return ScannerResult(scanner=scanner,completed=False,
    errors=[ScannerError(scanner=scanner,kind='failure',message='synthetic failure')])
  findings=[]
  if name=='command_injection.py':
   rule='B602' if scanner=='bandit' else 'python.lang.security.audit.subprocess-shell-true.subprocess-shell-true'
   findings=[finding(scanner,name,3,rule,78)]
  elif scanner=='bandit' and name=='safe_subprocess.py':findings=[finding(scanner,name,2,'B603',78)]
  elif scanner=='bandit' and name=='weak_hash.py':findings=[finding(scanner,name,2,'B324',327)]
  return ScannerResult(scanner=scanner,version=f'{scanner}-version',config_identity=kwargs.get('config_identity','default'),
   findings=findings,scanned_files=[name])
 return scan

def test_runner_metrics_reproducibility_and_agreement(monkeypatch):
 expected_dirty=bool(subprocess.run(['git','status','--porcelain'],capture_output=True,
  text=True,check=True).stdout.strip())
 monkeypatch.setattr('evaluation.runner.bandit.scan',fake_scan('bandit'))
 monkeypatch.setattr('evaluation.runner.semgrep.scan',fake_scan('semgrep'))
 report=run_evaluation(MANIFEST,EvaluationConfig(semgrep_config=str(RULES)))
 assert report.report_kind=='synthetic_harness_test' and report.synthetic_results_not_performance_claims
 assert len(report.results)==18
 assert report.metrics_by_mode['bandit'].model_dump(include={'true_positives','false_positives','true_negatives','false_negatives','unscorable'})=={
  'true_positives':2,'false_positives':1,'true_negatives':1,'false_negatives':1,'unscorable':1}
 assert report.metrics_by_mode['semgrep'].true_positives==1
 assert report.metrics_by_mode['semgrep'].false_negatives==2
 assert report.deduplication_merged_count==1
 assert report.raw_findings_count==4 and report.deduplicated_findings_count==3
 assert report.scanner_agreement=={'both_detect':1,'bandit_only':2,'neither_detect':2,'unavailable':1}
 assert report.changed_line_metrics_by_mode['bandit'].true_positives==1
 r=report.reproducibility
 assert r.sentinelreview_commit and r.working_tree_dirty is expected_dirty and r.dataset_version=='1.0.0'
 assert r.bandit_version=='bandit-version' and r.semgrep_version=='semgrep-version'
 assert r.semgrep_config_sha256 and len(r.manifest_sha256)==64 and len(r.fixture_sha256)==6
 assert not r.ai_enabled and report.ai_metrics is None

def test_partial_scanner_failure_not_clean_negative(monkeypatch):
 monkeypatch.setattr('evaluation.runner.bandit.scan',fake_scan('bandit'))
 monkeypatch.setattr('evaluation.runner.semgrep.scan',fake_scan('semgrep',{'clean_control'}))
 report=run_evaluation(MANIFEST,EvaluationConfig(semgrep_config=str(RULES)))
 rows={(r.case_id,r.mode):r for r in report.results}
 assert rows['synthetic-clean-negative','semgrep'].status=='scanner_error'
 assert rows['synthetic-clean-negative','combined'].status=='scanner_error'
 assert report.metrics_by_mode['semgrep'].scanner_errors==1

def test_positive_detection_survives_other_scanner_failure(monkeypatch):
 monkeypatch.setattr('evaluation.runner.bandit.scan',fake_scan('bandit'))
 monkeypatch.setattr('evaluation.runner.semgrep.scan',fake_scan('semgrep',{'command_injection'}))
 report=run_evaluation(MANIFEST,EvaluationConfig(semgrep_config=str(RULES)))
 row=next(r for r in report.results if r.case_id=='synthetic-command-positive' and r.mode=='combined')
 assert row.status=='tp' and row.scanner_errors

def test_optional_ai_metrics_never_invokes_provider(monkeypatch):
 monkeypatch.setattr('evaluation.runner.bandit.scan',fake_scan('bandit'))
 monkeypatch.setattr('evaluation.runner.semgrep.scan',fake_scan('semgrep'))
 report=run_evaluation(MANIFEST,EvaluationConfig(semgrep_config=str(RULES),evaluate_ai=True,
  ai_provider='recorded',ai_model='recorded-model',ai_prompt_version='recorded-v1'))
 assert report.ai_metrics is not None
 assert report.ai_metrics.available_reviews==0
 assert report.ai_metrics.deterministic_misses_ai_cannot_recover==1
 assert report.reproducibility.ai_provider=='recorded'

def test_semgrep_config_validation(tmp_path):
 path=tmp_path/'rules.yml';path.write_text('rules: []\n')
 identity,digest,safe_identity=validate_semgrep_config(str(path))
 assert identity==str(path.resolve()) and len(digest)==64
 assert safe_identity.startswith('local:')
 assert validate_semgrep_config('p/security-audit')==('p/security-audit',None,'p/security-audit')
 with pytest.raises(ValueError):validate_semgrep_config(str(tmp_path/'missing'))
