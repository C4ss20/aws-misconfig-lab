"""Read-only checks for IAM JSON policy documents."""
import argparse
import json
from pathlib import Path
from .checks import analyze_file


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy',type=Path,help='Local IAM JSON document (no AWS API required)')
    parser.add_argument('--output',type=Path,help='Optional JSON report file')
    args=parser.parse_args()
    try:
        findings=analyze_file(args.policy)
    except (ValueError,OSError,json.JSONDecodeError) as exc:
        parser.error(f'Cannot analyze policy: {exc}')
    report={'policy_file':args.policy.name,'scope':'Offline structural checks; not effective-permission analysis',
            'findings':[finding.as_dict() for finding in findings]}
    rendered=json.dumps(report,indent=2,ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(rendered+'\n',encoding='utf-8')
        print(f'Wrote {len(findings)} findings to {args.output}')
    else:
        print(rendered)

if __name__ == '__main__': main()
