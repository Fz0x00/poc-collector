"""
两阶段 PoC 采集主流程

Stage 1: GitHub Search → README → LLM 筛选（快，便宜）
Stage 2: 候选仓库 → clone → 源码分析（深，完整报告）
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from github_client import search_repos_for_cve
from summarize import analyze, fetch_readme, fetch_meta, stage1_screen


def load_cve_list(cve_file):
    with open(cve_file) as f:
        data = json.load(f)
    if isinstance(data, list):
        if data and isinstance(data[0], str):
            return data
        elif data and isinstance(data[0], dict):
            for key in ['cve_id', 'id', 'CVE']:
                if key in data[0]:
                    return [item[key] for item in data if key in item]
    elif isinstance(data, dict):
        return list(data.keys())
    raise ValueError(f'Cannot parse CVE list from {cve_file}')


def process_cve(cve_id, api_key, token=None, lang='zh', model='gpt-4o-mini',
                max_repos=10):
    """
    处理单个 CVE：Stage 1 筛选 + Stage 2 深度分析。
    """
    print(f'\n{"="*50}')
    print(f'[{cve_id}]')
    print(f'{"="*50}')

    # Step 1: GitHub Search
    print(f'  搜索 GitHub...', file=sys.stderr)
    candidates = search_repos_for_cve(cve_id, token, max_repos)
    if not candidates:
        print(f'  无结果', file=sys.stderr)
        return {'cve_id': cve_id, 'repos': []}

    print(f'  找到 {len(candidates)} 个仓库', file=sys.stderr)

    # Step 2: Stage 1 — README 筛选
    print(f'\n  --- Stage 1: README 筛选 ---', file=sys.stderr)
    survivors = []
    for cand in candidates:
        owner, name = cand['owner'], cand['name']
        print(f'\n  📋 {owner}/{name}', file=sys.stderr)

        try:
            meta = fetch_meta(owner, name, token)
            readme = fetch_readme(owner, name, token)
        except SystemExit:
            continue

        if not readme:
            print(f'    ⚠ 无 README，跳过', file=sys.stderr)
            continue

        screen = stage1_screen(owner, name, meta, readme, api_key, model=model)
        verdict = screen.get('verdict', 'skip')
        category = screen.get('brief_category', '')
        reason = screen.get('reason', '')

        if verdict == 'skip':
            print(f'    ⏭ 跳过 ({category}): {reason[:60]}', file=sys.stderr)
        else:
            print(f'    ✓ 候选 ({category}): {reason[:60]}', file=sys.stderr)
            survivors.append({
                'owner': owner,
                'name': name,
                'meta': meta,
                'brief_category': category,
                'screen_reason': reason,
            })

    print(f'\n  Stage 1 结果: {len(candidates)} → {len(survivors)} 候选', file=sys.stderr)

    if not survivors:
        return {'cve_id': cve_id, 'repos': []}

    # Step 3: Stage 2 — 深度分析
    print(f'\n  --- Stage 2: 源码深度分析 ---', file=sys.stderr)
    repos = []
    for surv in survivors:
        owner, name = surv['owner'], surv['name']
        print(f'\n  🔍 {owner}/{name}', file=sys.stderr)

        result = analyze(
            owner=owner,
            name=name,
            api_key=api_key,
            token=token,
            lang=lang,
            model=model,
            skip_stage1=True,  # Stage 1 已完成
        )
        repos.append(result)

    return {'cve_id': cve_id, 'repos': repos}


def build_report(all_results):
    stats = {
        'total_cves': len(all_results),
        'cves_with_repos': sum(1 for r in all_results if r.get('repos')),
        'total_repos_analyzed': sum(
            sum(1 for repo in r.get('repos', []) if repo.get('verdict') == 'analyzed')
            for r in all_results
        ),
        'repos_skipped': sum(
            sum(1 for repo in r.get('repos', []) if repo.get('verdict') == 'skip')
            for r in all_results
        ),
        'by_category': {},
    }
    for r in all_results:
        for repo in r.get('repos', []):
            if repo.get('verdict') == 'analyzed':
                cat = repo.get('category', 'unknown')
                stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

    return {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'stats': stats,
        'results': {r['cve_id']: r for r in all_results},
    }


def main():
    parser = argparse.ArgumentParser(description='两阶段 PoC 采集')
    parser.add_argument('--cve-file', default='data/chromium-cves.json')
    parser.add_argument('--output', default='data/poc-results.json')
    parser.add_argument('--token', default=None)
    parser.add_argument('--api-key', default=None)
    parser.add_argument('--model', default='gpt-4o-mini')
    parser.add_argument('--lang', default='zh', choices=['en', 'zh'])
    parser.add_argument('--max-cves', type=int, default=0)
    parser.add_argument('--max-repos', type=int, default=10)
    args = parser.parse_args()

    token = args.token or os.environ.get('GITHUB_TOKEN')
    api_key = args.api_key or os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print('需要设置 OPENAI_API_KEY', file=sys.stderr)
        sys.exit(1)

    cve_list = load_cve_list(args.cve_file)
    if args.max_cves > 0:
        cve_list = cve_list[:args.max_cves]

    print(f'处理 {len(cve_list)} 个 CVE', file=sys.stderr)

    all_results = []
    for i, cve_id in enumerate(cve_list):
        print(f'\n\n{"#"*60}', file=sys.stderr)
        print(f'# [{i+1}/{len(cve_list)}] {cve_id}', file=sys.stderr)
        print(f'{"#"*60}', file=sys.stderr)

        result = process_cve(cve_id, api_key, token, args.lang, args.model, args.max_repos)
        all_results.append(result)

    report = build_report(all_results)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f'\n\n{"="*60}', file=sys.stderr)
    print(f'报告已保存: {args.output}', file=sys.stderr)
    print(f'CVE 总数: {report["stats"]["total_cves"]}', file=sys.stderr)
    print(f'有结果的 CVE: {report["stats"]["cves_with_repos"]}', file=sys.stderr)
    print(f'分析的仓库: {report["stats"]["total_repos_analyzed"]}', file=sys.stderr)
    print(f'跳过的仓库: {report["stats"]["repos_skipped"]}', file=sys.stderr)
    print(f'分类: {report["stats"]["by_category"]}', file=sys.stderr)


if __name__ == '__main__':
    main()
