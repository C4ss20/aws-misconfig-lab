"""Simple structural checks for identity-based AWS IAM JSON policies.

NOT a complete AWS permission simulation or proof of effective access.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import json

PRIVILEGE_ACTIONS={
    'iam:passrole','iam:attachrolepolicy','iam:attachuserpolicy','iam:putrolepolicy',
    'iam:putuserpolicy','iam:createpolicyversion','iam:setdefaultpolicyversion',
    'iam:updaterole','iam:updateassumerolepolicy'
}

@dataclass(frozen=True)
class Finding:
    severity: str
    check_id: str
    statement: int
    finding: str
    remediation: str

    def as_dict(self): return asdict(self)


def _tokens(raw) -> list[str]:
    if isinstance(raw,str): return [raw.lower()]
    if isinstance(raw,list) and all(isinstance(i,str) for i in raw):return [s.lower() for s in raw]
    raise ValueError('Action/Resource must be a string or list of strings')


def inspect_policy(doc:dict) -> list[Finding]:
    if not isinstance(doc,dict):raise ValueError('Expected JSON object IAM policy')
    statements=doc.get('Statement')
    if isinstance(statements,dict):statements=[statements]
    if not isinstance(statements,list):raise ValueError('IAM policy needs Statement array or object')
    out=[]
    for idx,statement in enumerate(statements, start=1):
        if not isinstance(statement,dict):raise ValueError('Each statement must be an object')
        if str(statement.get('Effect','')).lower()!='allow':continue
        if 'NotAction' in statement or 'NotResource' in statement:
            out.append(Finding('REVIEW','IAM-000',idx,'NotAction/NotResource semantics require manual policy evaluation',
                'Review effective permissions using IAM Access Analyzer and relevant context.'))
            continue
        actions=_tokens(statement.get('Action',[]))
        resources=_tokens(statement.get('Resource',[]))
        all_resources='*' in resources
        all_actions='*' in actions or 'iam:*' in actions
        broad_action=any(a.endswith(':*') for a in actions)
        if all_actions and all_resources:
            out.append(Finding('CRITICAL','IAM-001',idx,'Wildcard high-privilege actions over all resources',
                'Replace with an allowlist of actions and ARNs; validate with IAM Access Analyzer.'))
        elif broad_action and all_resources:
            out.append(Finding('HIGH','IAM-002',idx,'Service-wide action wildcard with all resources',
                'Reduce action scope and apply resource ARNs where supported.'))
        if all_resources and (PRIVILEGE_ACTIONS & set(actions)):
            out.append(Finding('HIGH','IAM-003',idx,'Identity/role privilege-management actions over all resources',
                'Scope affected role/policy resources, set conditions, review privilege escalation pathways.'))
        if 'sts:assumerole' in actions and all_resources:
            out.append(Finding('MEDIUM','IAM-004',idx,'AssumeRole allowed on any role ARN',
                'Scope target role ARNs and review trust policies and external IDs where relevant.'))
        if not actions and not ('NotAction' in statement):
            out.append(Finding('REVIEW','IAM-005',idx,'Allow statement has no explicit Action',
                'Check IAM JSON structure and policy syntax.'))
    return out


def analyze_file(path:Path) -> list[Finding]:
    return inspect_policy(json.loads(path.read_text(encoding='utf-8')))
