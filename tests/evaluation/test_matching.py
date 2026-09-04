import pytest
from evaluation.matching import classify,on_changed_line,record,target_match
from evaluation.models import MappingEntry,MatchingPolicy,LineRange


def test_exact_cwe_and_range(case_factory,finding_factory):
 case=case_factory();finding=finding_factory()
 assert target_match(case,finding,MatchingPolicy())
 assert not target_match(case,finding_factory(line_number=7),MatchingPolicy())
 assert not target_match(case,finding_factory(filename='other.py'),MatchingPolicy())
 assert not target_match(case,finding_factory(cwe_id=89),MatchingPolicy())

def test_reviewed_mapping(case_factory,finding_factory):
 case=case_factory(cwe_ids=[],expected_category='command-injection')
 policy=MatchingPolicy(version='reviewed-v1',mappings=[MappingEntry(scanner='bandit',rule_id='B999',expected_category='command-injection')])
 assert target_match(case,finding_factory(cwe_id=None),policy)
 assert not target_match(case,finding_factory(cwe_id=None,rule_id='B998'),policy)
 assert not target_match(case,finding_factory(cwe_id=None),MatchingPolicy())

def test_records_and_changed_ranges(case_factory,finding_factory):
 case=case_factory();item=record(case,finding_factory(),MatchingPolicy())
 assert item.in_assessment_scope and item.target_match and item.changed_line is True
 assert on_changed_line(case,7) is False
 case.changed_line_ranges=None
 assert on_changed_line(case,5) is None

@pytest.mark.parametrize('present,detected,expected',[(True,True,'tp'),(True,False,'fn'),(False,True,'fp'),(False,False,'tn')])
def test_classification(case_factory,finding_factory,present,detected,expected):
 case=case_factory(vulnerability_present=present,vulnerable_line_range=None if not present else LineRange(start=5,end=5))
 records=[record(case,finding_factory(),MatchingPolicy())] if detected else []
 assert classify(case,records,MatchingPolicy())==(expected,detected)

def test_unscorable_and_scanner_failure(case_factory,finding_factory):
 case=case_factory(cwe_ids=[],expected_category='unknown')
 assert classify(case,[],MatchingPolicy())==('unscorable',None)
 assert classify(case,[],MatchingPolicy(),scanner_error=True)==('scanner_error',None)

def test_changed_line_effect(case_factory,finding_factory):
 case=case_factory(changed_line_ranges=[LineRange(start=1,end=2)])
 records=[record(case,finding_factory(),MatchingPolicy())]
 assert classify(case,records,MatchingPolicy())[0]=='tp'
 assert classify(case,records,MatchingPolicy(),changed_only=True)[0]=='fn'
 case.changed_line_ranges=None
 assert classify(case,records,MatchingPolicy(),changed_only=True)[0]=='unscorable'
