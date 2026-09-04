import json
import httpx
import pytest
from pydantic import ValidationError
from app.ai.base import ProviderError
from app.ai.models import ReviewOutput
from app.ai.provider import OpenAIProvider, create_provider, safe_identifier


def wire(output):
    return {"id": "resp_test123", "model": "test-model-snapshot", "status": "completed",
        "output": [{"type": "message", "role": "assistant", "content": [
            {"type": "output_text", "text": json.dumps(output)}]}]}


async def test_http_request_and_safe_metadata(ai_settings, ai_context, review_output):
    calls = []
    def handler(request):
        calls.append(request)
        data = json.loads(request.content)
        assert data['model'] == ai_settings.ai_model
        assert data['store'] is False and data['tools'] == []
        assert data['max_output_tokens'] == 1200
        assert data['text']['format']['strict'] is True
        assert data['text']['format']['schema']['additionalProperties'] is False
        assert json.loads(data['input'][0]['content']) == ai_context.model_dump()
        assert request.headers['Authorization'] == 'Bearer test-only-credential'
        return httpx.Response(200, json=wire(review_output), headers={
            'x-request-id': 'req_test123', 'authorization': 'never-return-this', 'x-private': 'hidden'})
    result = await OpenAIProvider(ai_settings, httpx.MockTransport(handler)).review(ai_context)
    assert len(calls) == 1
    assert result.output.verdict == 'needs_review'
    assert result.metadata.model_dump() == dict(reported_model='test-model-snapshot',
                                               response_id='resp_test123', request_id='req_test123')
    assert 'hidden' not in result.model_dump_json()


@pytest.mark.parametrize('status,kind,stop', [(401,'authentication',True),(403,'authentication',True),
    (429,'rate_limit',True),(500,'provider_http_error',False),(302,'provider_http_error',False)])
async def test_http_errors(ai_settings, ai_context, status, kind, stop):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(status, text='sensitive upstream body', headers={'location':'https://other.example'})
    with pytest.raises(ProviderError) as error:
        await OpenAIProvider(ai_settings, httpx.MockTransport(handler)).review(ai_context)
    assert error.value.error.kind == kind and error.value.stop == stop
    assert 'sensitive' not in str(error.value)
    assert len(calls) == 1


@pytest.mark.parametrize('exception,kind', [(httpx.ReadTimeout,'timeout'),(httpx.ConnectError,'unavailable')])
async def test_network_errors(ai_settings, ai_context, exception, kind):
    def handler(request):
        raise exception('sensitive exception details')
    with pytest.raises(ProviderError) as error:
        await OpenAIProvider(ai_settings, httpx.MockTransport(handler)).review(ai_context)
    assert error.value.error.kind == kind
    assert 'sensitive' not in str(error.value)


@pytest.mark.parametrize('mode', ['json','schema','refusal','incomplete','tool','oversized','multiple','not_object'])
async def test_bad_responses(ai_settings, ai_context, review_output, mode):
    data = wire(review_output)
    if mode == 'schema':
        data = wire({**review_output, 'priority':'urgent'})
    elif mode == 'refusal':
        data['output'][0]['content'] = [{'type':'refusal','refusal':'no'}]
    elif mode == 'incomplete':
        data['status'] = 'incomplete'
    elif mode == 'tool':
        data['output'] = [{'type':'function_call'}]
    elif mode == 'multiple':
        data['output'] *= 2
    elif mode == 'not_object':
        data = []
    content = json.dumps(data).encode()
    if mode == 'json':
        content = b'not json'
    elif mode == 'oversized':
        content = b'x' * (ai_settings.ai_max_response_bytes+1)
    with pytest.raises(ProviderError):
        await OpenAIProvider(ai_settings, httpx.MockTransport(lambda r: httpx.Response(200, content=content))).review(ai_context)


@pytest.mark.parametrize('changes', [{'confidence':-0.1},{'confidence':1.1},{'confidence':float('nan')},
    {'confidence':float('inf')},{'confidence':True},{'confidence':'0.6'},{'verdict':'safe'},
    {'exploitability':'certain'},{'impact':'critical'},{'priority':'urgent'},
    {'reasoning':''},{'remediation':'x'*1501},{'evidence_used':[]},{'extra':'not allowed'}])
def test_strict_schema(review_output, changes):
    with pytest.raises(ValidationError):
        ReviewOutput.model_validate({**review_output, **changes})


@pytest.mark.parametrize('field,value', [('ai_model',None),('ai_api_key',None),('ai_provider','other'),
    ('ai_endpoint','http://provider.example'),('ai_endpoint','https://user:pass@provider.example'),
    ('ai_endpoint','https://provider.example?key=hidden')])
def test_invalid_configuration(ai_settings, field, value):
    setattr(ai_settings, field, value)
    with pytest.raises(ProviderError) as error:
        create_provider(ai_settings)
    assert error.value.stop


def test_factory_and_identifier_filter(ai_settings):
    assert isinstance(create_provider(ai_settings), OpenAIProvider)
    assert safe_identifier('resp_abc') == 'resp_abc'
    assert safe_identifier('Bearer secret') is None
    assert safe_identifier('sk-' + 'a'*25) is None
    assert safe_identifier('test-only-credential', 'test-only-credential') is None
