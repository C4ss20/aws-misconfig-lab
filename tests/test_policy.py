import json
import unittest
from pathlib import Path
from iam_audit.checks import inspect_policy,analyze_file

BASE=Path(__file__).resolve().parents[1]

class PolicyTests(unittest.TestCase):
    def test_overly_permissive(self):
        findings=analyze_file(BASE/'examples/overly-permissive-policy.json')
        self.assertIn('IAM-001',[f.check_id for f in findings])
        self.assertIn('IAM-003',[f.check_id for f in findings])
    def test_scoped(self):
        self.assertEqual(analyze_file(BASE/'examples/scoped-policy.json'),[])
    def test_notaction_requires_review(self):
        result=inspect_policy({'Statement':[{'Effect':'Allow','NotAction':'iam:*','Resource':'*'}]})
        self.assertEqual(result[0].severity,'REVIEW')
    def test_notaction_no_false_wildcard_claim(self):
        result=inspect_policy({'Statement':[{'Effect':'Allow','NotAction':'s3:*','NotResource':'*'}]})
        self.assertEqual([x.check_id for x in result],['IAM-000'])
    def test_invalid_statement(self):
        with self.assertRaises(ValueError):inspect_policy({'Statement':'not a statement'})

if __name__=='__main__':unittest.main()
