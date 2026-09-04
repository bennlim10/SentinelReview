import hashlib,json
from pathlib import Path
import pytest
from pydantic import ValidationError
from evaluation.loader import load_manifest


def manifest(case): return {'dataset_name':'synthetic','dataset_version':'1','cases':[case]}
def base(code='pass\n'):
 return dict(case_id='one',source_dataset='synthetic',source_reference='local',source_revision='1',
  language='python',filename='a.py',vulnerability_present=True,cwe_ids=['CWE-78'],expected_category=None,
  vulnerable_line_range={'start':1,'end':1},assessment_line_range={'start':1,'end':1},code=code,
  fixture_path=None,code_sha256=hashlib.sha256(code.encode()).hexdigest(),pair_id=None,
  changed_line_ranges=None,notes='',label_provenance={'kind':'constructed_fixture','reference':'local','rationale':'test','reviewed_by':None},
  license={'identifier':None,'reference':'local'})

def write(tmp_path,data):
 p=tmp_path/'manifest.json';p.write_text(json.dumps(data));return p

def test_inline_loading(tmp_path):
 m,contents,mhash,hashes=load_manifest(write(tmp_path,manifest(base())))
 assert m.cases[0].case_id=='one' and contents['one']==b'pass\n'
 assert len(mhash)==64 and hashes['one']==m.cases[0].code_sha256

def test_fixture_loading(tmp_path):
 (tmp_path/'a.py').write_text('x=1\n');case=base();case.update(code=None,fixture_path='a.py',code_sha256=hashlib.sha256(b'x=1\n').hexdigest())
 assert load_manifest(write(tmp_path,manifest(case)))[1]['one']==b'x=1\n'

@pytest.mark.parametrize('change',[
 {'vulnerable_line_range':None}, {'assessment_line_range':{'start':2,'end':1}},
 {'code':None,'fixture_path':None}, {'fixture_path':'../a.py','code':None},
 {'cwe_ids':['78']}, {'cwe_ids':[],'expected_category':None},
 {'language':'javascript'}, {'code':'x','fixture_path':'a.py'},
])
def test_invalid_cases(tmp_path,change):
 case=base();case.update(change)
 with pytest.raises((ValidationError,ValueError)): load_manifest(write(tmp_path,manifest(case)))

def test_negative_scope_rules(tmp_path):
 case=base();case.update(vulnerability_present=False,vulnerable_line_range=None)
 assert load_manifest(write(tmp_path,manifest(case)))[0].cases[0].assessment_line_range.start==1
 case['vulnerable_line_range']={'start':1,'end':1}
 with pytest.raises(ValidationError):load_manifest(write(tmp_path,manifest(case)))

def test_hash_and_size(tmp_path):
 case=base();case['code_sha256']='0'*64;p=write(tmp_path,manifest(case))
 with pytest.raises(ValueError,match='hash'):load_manifest(p)
 case=base('long')
 with pytest.raises(ValueError,match='size'):load_manifest(write(tmp_path,manifest(case)),max_fixture_bytes=2)

def test_duplicate_ids(tmp_path):
 case=base()
 with pytest.raises(ValidationError,match='unique'):load_manifest(write(tmp_path,{'dataset_name':'x','dataset_version':'1','cases':[case,case]}))

def test_scope_must_exist_in_fixture(tmp_path):
 case=base();case['assessment_line_range']={'start':1,'end':2}
 with pytest.raises(ValueError,match='scope'):load_manifest(write(tmp_path,manifest(case)))
