import asyncio
import json
import pytest
from app.ai.base import ProviderError
from app.ai.models import ProviderResult, ProviderMetadata, ReviewOutput
from app.ai.prompts import PROMPT_VERSION
from app.services.reasoning import review_findings


class FakeProvider:
    def __init__(self, output, failures=None):
        self.output = output
        self.failures = failures or {}
        self.contexts = []

    async def review(self, context):
        index = len(self.contexts)
        self.contexts.append(context)
        if index in self.failures:
            raise self.failures[index]
        return ProviderResult(output=ReviewOutput.model_validate(self.output),
            metadata=ProviderMetadata(reported_model='fake-model',response_id=f'fake-response-{index}'))


def install(monkeypatch, output, failures=None):
    provider = FakeProvider(output, failures)
    monkeypatch.setattr('app.services.reasoning.create_provider', lambda settings: provider)
    return provider


def deterministic(response):
    return response.model_dump(exclude={'ai_complete','ai_summary','findings'}) | {
        'findings':[f.model_dump(exclude={'ai_review'}) for f in response.findings]}


async def test_disabled_no_provider(monkeypatch, settings, ai_response, ai_contents):
    monkeypatch.setattr('app.services.reasoning.create_provider', lambda s: pytest.fail('provider constructed'))
    before = deterministic(ai_response)
    await review_findings(ai_response, ai_contents, {}, settings)
    assert deterministic(ai_response) == before
    assert ai_response.ai_complete and ai_response.analysis_complete
    assert ai_response.ai_summary.ai_findings_requested == 0
    assert ai_response.ai_summary.ai_findings_disabled == 4
    assert all(f.ai_review.status=='disabled' for f in ai_response.findings)


async def test_success_selection_metadata(monkeypatch, ai_settings, ai_response, ai_contents, review_output):
    provider = install(monkeypatch, review_output)
    before = deterministic(ai_response)
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert [c.finding.line_number for c in provider.contexts] == [8,5,2]
    assert deterministic(ai_response) == before
    summary = ai_response.ai_summary
    assert summary.ai_findings_selected == summary.ai_findings_requested == summary.ai_findings_completed == 3
    assert summary.ai_findings_failed == 0 and summary.ai_findings_skipped == 1
    assert summary.ai_verdict_counts == {'needs_review':3}
    assert summary.ai_priority_counts == {'high':3}
    assert summary.prompt_version == PROMPT_VERSION
    assert summary.configured_provider == 'openai' and summary.configured_model == 'test-model'
    assert summary.ai_runtime_seconds >= 0
    assert ai_response.ai_complete
    reviewed = ai_response.findings[1]
    assert reviewed.severity == 'LOW' and reviewed.ai_review.result.priority == 'high'
    assert reviewed.confidence == 'HIGH' and reviewed.ai_review.result.confidence == 0.6
    assert reviewed.ai_review.provider_metadata.reported_model == 'fake-model'
    assert reviewed.ai_review.context_id and reviewed.ai_review.finding_id


@pytest.mark.parametrize('failure', [ProviderError('unavailable','Provider unavailable'),ValueError('private message')])
async def test_partial_failure_preserves_findings(monkeypatch, ai_settings, ai_response, ai_contents, review_output, failure):
    provider = install(monkeypatch, review_output, {0:failure})
    before = deterministic(ai_response)
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert len(provider.contexts)==3
    assert deterministic(ai_response)==before
    assert not ai_response.ai_complete and ai_response.analysis_complete
    assert ai_response.ai_summary.ai_findings_completed==2
    assert ai_response.ai_summary.ai_findings_failed==1
    assert 'private message' not in ai_response.model_dump_json()


@pytest.mark.parametrize('kind', ['authentication','rate_limit'])
async def test_stop_without_retries(monkeypatch, ai_settings, ai_response, ai_contents, review_output, kind):
    provider = install(monkeypatch, review_output, {0:ProviderError(kind,'Provider stopped',stop=True)})
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert len(provider.contexts)==1
    assert not ai_response.ai_complete
    summary=ai_response.ai_summary
    assert summary.ai_findings_selected==3 and summary.ai_findings_requested==1
    assert summary.ai_findings_failed==1 and summary.ai_findings_skipped==3
    assert sum(f.ai_review.selected and f.ai_review.status=='skipped' for f in ai_response.findings)==2


async def test_timeout(monkeypatch, ai_settings, ai_response, ai_contents):
    class Slow:
        async def review(self, context):
            await asyncio.sleep(1)
    monkeypatch.setattr('app.services.reasoning.create_provider',lambda s:Slow())
    ai_settings.ai_timeout_seconds=0.001
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert ai_response.ai_summary.ai_findings_failed==3
    assert not ai_response.ai_complete
    assert all(f.ai_review.error.kind=='timeout' for f in ai_response.findings if f.ai_review.status=='failed')


@pytest.mark.parametrize('refs', [['code:999'], ['scanner:0','scanner:0'], ['invented:0']])
async def test_invalid_evidence(monkeypatch, ai_settings, ai_response, ai_contents, review_output, refs):
    install(monkeypatch,{**review_output,'evidence_used':refs})
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert ai_response.ai_summary.ai_findings_failed==3
    assert not ai_response.ai_complete
    assert all(f.ai_review.result is None for f in ai_response.findings)


async def test_invalid_custom_provider_schema(monkeypatch, ai_settings, ai_response, ai_contents):
    class Invalid:
        async def review(self, context):
            return {'output':{'priority':'bad'}}
    monkeypatch.setattr('app.services.reasoning.create_provider',lambda s:Invalid())
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert ai_response.ai_summary.ai_findings_failed==3
    assert not ai_response.ai_complete


async def test_changed_lines_only(monkeypatch, ai_settings, ai_response, ai_contents, review_output):
    provider=install(monkeypatch,review_output)
    ai_settings.ai_changed_lines_only=True
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert [c.finding.line_number for c in provider.contexts]==[8,5]
    assert ai_response.ai_complete
    assert ai_response.ai_summary.ai_findings_selected==2
    assert ai_response.ai_summary.ai_findings_skipped==2
    assert ai_response.findings[3].ai_review.skip_reason=='changed_line_filter'


@pytest.mark.parametrize('mode', ['zero_limit','no_findings','no_eligible'])
async def test_nothing_expected(monkeypatch, ai_settings, ai_response, ai_contents, mode):
    monkeypatch.setattr('app.services.reasoning.create_provider',lambda s:pytest.fail('provider constructed'))
    if mode=='zero_limit':
        ai_settings.ai_max_findings=0
    elif mode=='no_findings':
        ai_response.findings=[]
    else:
        ai_settings.ai_changed_lines_only=True
        for f in ai_response.findings:
            f.is_on_changed_line=None
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert ai_response.ai_complete
    assert ai_response.ai_summary.ai_findings_requested==0
    assert ai_response.ai_summary.ai_findings_selected==0


async def test_missing_config_is_skipped_not_success(ai_settings, ai_response, ai_contents):
    ai_settings.ai_api_key=None
    before=deterministic(ai_response)
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert deterministic(ai_response)==before
    assert not ai_response.ai_complete
    assert ai_response.ai_summary.ai_findings_requested==0
    assert ai_response.ai_summary.ai_findings_completed==0
    assert ai_response.ai_summary.errors[0].kind=='configuration'


async def test_context_failure_is_selected_skip(monkeypatch, ai_settings, ai_response, ai_contents, review_output):
    provider=install(monkeypatch,review_output)
    ai_contents['a.py']=b'x'*20000+b'\n'+b'x'*20000
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert not provider.contexts
    assert not ai_response.ai_complete
    assert ai_response.ai_summary.ai_findings_selected==3
    assert ai_response.ai_summary.ai_findings_skipped==4


async def test_export(monkeypatch, tmp_path, ai_settings, ai_response, ai_contents, review_output):
    install(monkeypatch,review_output)
    path=tmp_path/'evaluation.json'
    ai_settings.ai_evaluation_output=str(path)
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    saved=json.loads(path.read_text())
    assert len(saved['records'])==4
    assert saved['ai_summary']['prompt_version']==PROMPT_VERSION
    assert all(r['expected_label'] is None for r in saved['records'])
    assert saved['records'][0]['ai_review']['context_id']
    assert 'value_1' not in path.read_text()
    assert ai_settings.ai_api_key.get_secret_value() not in path.read_text()
    assert not ai_response.ai_summary.export_error


async def test_export_failure_isolated(monkeypatch, tmp_path, ai_settings, ai_response, ai_contents, review_output):
    install(monkeypatch,review_output)
    ai_settings.ai_evaluation_output=str(tmp_path/'missing'/'evaluation.json')
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert ai_response.ai_complete and ai_response.analysis_complete
    assert ai_response.ai_summary.export_error.kind=='export_failed'


async def test_output_credential_rejected(monkeypatch, ai_settings, ai_response, ai_contents, review_output):
    install(monkeypatch,{**review_output,'reasoning':ai_settings.ai_api_key.get_secret_value()})
    await review_findings(ai_response, ai_contents, {}, ai_settings)
    assert ai_response.ai_summary.ai_findings_failed==3
    assert ai_settings.ai_api_key.get_secret_value() not in ai_response.model_dump_json()


@pytest.mark.usefixtures('offline_semgrep')
async def test_full_analysis_keeps_deterministic_data(monkeypatch, github, ai_settings, review_output):
    from app.services.analysis import analyze
    from app.models import AnalysisRequest
    request=AnalysisRequest(repository='owner/repo',pull_request_number=1)
    ai_settings.ai_enabled=False
    baseline=await analyze(request,github,ai_settings)
    ai_settings.ai_enabled=True
    install(monkeypatch,review_output)
    enriched=await analyze(request,github,ai_settings)
    assert deterministic(enriched)==deterministic(baseline)
    assert enriched.ai_summary.ai_findings_completed>0
    assert enriched.ai_complete
