"""
Generate Markdown report from poc-results.json.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime


CATEGORY_EMOJI = {
    'exploit': '🔴',
    'poc': '🟠',
    'detection': '🟡',
    'analysis': '🔵',
    'unrelated': '⚪',
    'malware': '☠️',
    'unclassified': '❓',
}


def generate_markdown(report: dict) -> str:
    """Generate Markdown from poc-results JSON."""
    stats = report.get('stats', {})
    results = report.get('results', {})
    generated = report.get('generated_at', 'unknown')

    lines = [
        f'# PoC Collector Report',
        f'',
        f'> Generated: {generated}',
        f'',
        f'## Summary',
        f'',
        f'| Metric | Count |',
        f'|--------|-------|',
        f'| CVEs searched | {stats.get("total_cves_searched", 0)} |',
        f'| CVEs with repos | {stats.get("cves_with_results", 0)} |',
        f'| Total repos found | {stats.get("total_repos", 0)} |',
        f'',
    ]

    # Category breakdown
    by_cat = stats.get('by_category', {})
    if by_cat:
        lines.append('### By Category')
        lines.append('')
        lines.append('| Category | Count |')
        lines.append('|----------|-------|')
        for cat in ['exploit', 'poc', 'detection', 'analysis', 'unrelated', 'malware', 'unclassified']:
            count = by_cat.get(cat, 0)
            if count > 0:
                emoji = CATEGORY_EMOJI.get(cat, '?')
                lines.append(f'| {emoji} {cat} | {count} |')
        lines.append('')

    # CVE details (only show CVEs with exploit/poc repos)
    lines.append('## CVEs with PoC/Exploit')
    lines.append('')

    cve_entries = []
    for cve_id, cve_data in sorted(results.items()):
        repos = cve_data.get('repos', [])
        # Filter to exploit/poc only
        exploit_repos = [r for r in repos if r.get('category') in ('exploit', 'poc')]
        if not exploit_repos:
            continue
        cve_entries.append((cve_id, exploit_repos))

    if not cve_entries:
        lines.append('*No CVEs with confirmed PoC/exploit found.*')
        lines.append('')
    else:
        for cve_id, exploit_repos in cve_entries:
            lines.append(f'### {cve_id}')
            lines.append('')
            lines.append('| Repo | Stars | Category | Confidence | Reason |')
            lines.append('|------|-------|----------|------------|--------|')
            for repo in exploit_repos:
                cat = repo.get('category', '?')
                emoji = CATEGORY_EMOJI.get(cat, '?')
                stars = repo.get('stars', 0)
                conf = repo.get('confidence', 0)
                reason = repo.get('reason', '')[:60]
                name = repo.get('name', '?')
                lines.append(f'| [{name}]({repo["url"]}) | {stars} | {emoji} {cat} | {conf:.0%} | {reason} |')
            lines.append('')

    # Detection tools summary
    detection_cves = []
    for cve_id, cve_data in sorted(results.items()):
        repos = cve_data.get('repos', [])
        det_repos = [r for r in repos if r.get('category') == 'detection']
        if det_repos:
            detection_cves.append((cve_id, det_repos))

    if detection_cves:
        lines.append('## Detection Tools')
        lines.append('')
        for cve_id, det_repos in detection_cves[:20]:
            repo_names = ', '.join(f'[{r["name"]}]({r["url"]})' for r in det_repos[:3])
            lines.append(f'- **{cve_id}**: {repo_names}')
        lines.append('')

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Generate Markdown report from poc-results.json')
    parser.add_argument('--input', default='data/poc-results.json')
    parser.add_argument('--output', default='data/poc-report.md')
    args = parser.parse_args()

    with open(args.input) as f:
        report = json.load(f)

    md = generate_markdown(report)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        f.write(md)

    print(f'Report written to {args.output}')


if __name__ == '__main__':
    main()
