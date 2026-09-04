import json
import pytest
from datetime import datetime,timezone
from evaluation.models import EvaluationReport,Reproducibility,BinaryMetrics
from evaluation.reports import write_reports


def report():
 repro=Reproducibility(sentinelreview_commit='abc',working_tree_dirty=True,dataset_name='synthetic',
  dataset_version='1',manifest_sha256='a'*64,fixture_sha256={'x':'b'*64},bandit_version='1',semgrep_version='2',
  semgrep_config_identity='local',semgrep_config_sha256='c'*64,ai_enabled=False,
  run_timestamp_utc=datetime.now(timezone.utc),platform='test',python_version='3.12',configuration={})
 return EvaluationReport(report_kind='synthetic_harness_test',synthetic_results_not_performance_claims=True,
  reproducibility=repro,results=[],metrics_by_mode={'bandit':BinaryMetrics()},findings_per_case={},
  findings_by_scanner={},findings_by_cwe={},scanner_agreement={},raw_findings_count=0,
  deduplicated_findings_count=0,deduplication_merged_count=0,
  changed_line_metrics_by_mode={'bandit':None},ai_metrics=None,total_runtime_seconds=0,
  report_label='REAL-WORLD PILOT — TEST')

def test_json_and_markdown(tmp_path):
 jp,mp=write_reports(report(),tmp_path,'run')
 assert json.loads(jp.read_text())['reproducibility']['sentinelreview_commit']=='abc'
 assert EvaluationReport.model_validate_json(jp.read_text()).report_kind == 'synthetic_harness_test'
 assert 'not benchmark performance claims' in mp.read_text()
 assert 'undefined' in mp.read_text()
 assert 'REAL-WORLD PILOT — TEST' in mp.read_text()
 with pytest.raises(ValueError):write_reports(report(),tmp_path,'../escape')
