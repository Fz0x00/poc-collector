"""
Main orchestrator: runs the full PoC collection pipeline.

Pipeline:
1. Load CVE list from chromium-cves.json
2. For each CVE, search GitHub for related repos
3. Fetch repo data (metadata + README + file tree)
4. Rule-based pre-filter (skip LLM for clear cases)
5. LLM classification for uncertain repos
6. Output poc-results.json
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from github_client import search_repos_for_cve, fetch_repo_full
from classify_rules import classify_by_rules
from classify_llm import classify_batch


def load_cve_list(cve_file: str) -> list[str]:
    """Load CVE IDs from chromium-cves.json or a text file."""
    with open(cve_file) as f:
        data = json.load(f)

    if isinstance(data, list):
        # Could be list of strings or list of dicts
        if data and isinstance(data[0], str):
            return data
        elif data and isinstance(data[0], dict):
            # Extract CVE IDs from dict
            for key in ['cve_id', 'id', 'CVE']:
                if key in data[0]:
                    return [item[key] for item in data if key in item]
    elif isinstance(data, dict):
        return list(data.keys())

    raise ValueError(f'Cannot parse CVE list from {cve_file}')


def collect_for_cve(cve_id: str, token: str | None = None,
                    max_repos: int = 30) -> dict:
    """
    Collect and classify repos for a single CVE.
    Returns {cve_id, repos: [{url, stars, language, category, confidence, reason, ...}]}.
    """
    print(f'  Searching GitHub for {cve_id}...')
    candidates = search_repos_for_cve(cve_id, token, max_repos)

    if not candidates:
        return {'cve_id': cve_id, 'repos': []}

    print(f'  Found {len(candidates)} repos, fetching data...')
    repos_with_data = []
    for cand in candidates:
        try:
            full = fetch_repo_full(cand['owner'], cand['name'], token)
            repos_with_data.append({
                **cand,
                'metadata': full['metadata'],
                'readme': full['readme'],
                'files': full['files'],
            })
        except Exception as e:
            print(f'    Failed to fetch {cand["owner"]}/{cand["name"]}: {e}')
            repos_with_data.append({
                **cand,
                'metadata': {},
                'readme': '',
                'files': [],
            })

    return {'cve_id': cve_id, 'repos': repos_with_data}


def classify_repos(cve_id: str, repos: list[dict], token: str | None = None,
                   api_key: str | None = None, api_base: str | None = None,
                   model: str = 'gpt-4o-mini') -> list[dict]:
    """
    Classify repos: rule-based first, then LLM for uncertain ones.
    Returns list of classified repos.
    """
    results = []
    llm_batch = []

    for repo in repos:
        rule_result = classify_by_rules(
            owner=repo['owner'],
            name=repo['name'],
            stars=repo.get('stars', 0),
            description=repo.get('description', ''),
            readme=repo.get('readme', ''),
            files=repo.get('files', []),
        )
        if rule_result:
            category, confidence, reason = rule_result
            results.append({
                'url': repo['url'],
                'owner': repo['owner'],
                'name': repo['name'],
                'stars': repo.get('stars', 0),
                'language': repo.get('language'),
                'description': repo.get('description', ''),
                'category': category,
                'confidence': confidence,
                'classified_by': 'rules',
                'reason': reason,
                'readme_snippet': repo.get('readme', '')[:200],
            })
        else:
            llm_batch.append(repo)

    # LLM classification for uncertain repos
    if llm_batch and api_key:
        print(f'    LLM classifying {len(llm_batch)} repos...')
        llm_results = classify_batch(
            cve_id=cve_id,
            repos=llm_batch,
            api_key=api_key,
            api_base=api_base or 'https://api.openai.com/v1',
            model=model,
        )
        for repo, llm_result in zip(llm_batch, llm_results):
            results.append({
                'url': repo['url'],
                'owner': repo['owner'],
                'name': repo['name'],
                'stars': repo.get('stars', 0),
                'language': repo.get('language'),
                'description': repo.get('description', ''),
                'category': llm_result.get('category', 'unrelated'),
                'confidence': llm_result.get('confidence', 0.3),
                'classified_by': llm_result.get('classified_by', 'llm'),
                'reason': llm_result.get('reason', ''),
                'readme_snippet': repo.get('readme', '')[:200],
            })
    elif llm_batch:
        print(f'    Skipping {len(llm_batch)} repos (no LLM API key)')
        for repo in llm_batch:
            results.append({
                'url': repo['url'],
                'owner': repo['owner'],
                'name': repo['name'],
                'stars': repo.get('stars', 0),
                'language': repo.get('language'),
                'description': repo.get('description', ''),
                'category': 'unclassified',
                'confidence': 0.0,
                'classified_by': 'none',
                'reason': 'No LLM API key available',
                'readme_snippet': repo.get('readme', '')[:200],
            })

    # Sort by confidence descending
    results.sort(key=lambda x: x.get('confidence', 0), reverse=True)
    return results


def build_report(results: dict) -> dict:
    """Build final report from collected results."""
    stats = {
        'total_cves_searched': len(results),
        'cves_with_results': sum(1 for r in results.values() if r.get('repos')),
        'total_repos': sum(len(r.get('repos', [])) for r in results.values()),
        'by_category': {},
    }

    for cve_data in results.values():
        for repo in cve_data.get('repos', []):
            cat = repo.get('category', 'unclassified')
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

    return {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'stats': stats,
        'results': results,
    }


def main():
    parser = argparse.ArgumentParser(description='Collect and classify PoC/exploit repos for Chromium CVEs')
    parser.add_argument('--cve-file', default='data/chromium-cves.json',
                        help='Path to CVE list (JSON)')
    parser.add_argument('--output', default='data/poc-results.json',
                        help='Output file path')
    parser.add_argument('--token', default=None,
                        help='GitHub token (or GITHUB_TOKEN env)')
    parser.add_argument('--api-key', default=None,
                        help='LLM API key (or OPENAI_API_KEY env)')
    parser.add_argument('--api-base', default=None,
                        help='LLM API base URL (default: https://api.openai.com/v1)')
    parser.add_argument('--model', default='gpt-4o-mini',
                        help='LLM model name')
    parser.add_argument('--max-cves', type=int, default=0,
                        help='Max CVEs to process (0 = all)')
    parser.add_argument('--max-repos', type=int, default=30,
                        help='Max repos per CVE')
    parser.add_argument('--skip-fetch', action='store_true',
                        help='Skip GitHub fetch, use cached data only')
    parser.add_argument('--cache-dir', default='data/cache',
                        help='Cache directory for raw repo data')
    args = parser.parse_args()

    token = args.token or os.environ.get('GITHUB_TOKEN')
    api_key = args.api_key or os.environ.get('OPENAI_API_KEY')

    if not token:
        print('Warning: No GitHub token. Rate limits will be strict (10 req/min).')

    # Load CVE list
    print(f'Loading CVE list from {args.cve_file}...')
    cve_list = load_cve_list(args.cve_file)
    if args.max_cves > 0:
        cve_list = cve_list[:args.max_cves]
    print(f'Processing {len(cve_list)} CVEs...')

    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    llm_calls = 0

    for i, cve_id in enumerate(cve_list):
        print(f'\n[{i+1}/{len(cve_list)}] {cve_id}')

        cache_file = cache_dir / f'{cve_id}.json'

        if args.skip_fetch and cache_file.exists():
            with open(cache_file) as f:
                cve_data = json.load(f)
            print(f'  Loaded from cache: {len(cve_data.get("repos", []))} repos')
        else:
            cve_data = collect_for_cve(cve_id, token, args.max_repos)
            # Cache raw data
            with open(cache_file, 'w') as f:
                json.dump(cve_data, f, indent=2)

        # Classify
        classified = classify_repos(
            cve_id=cve_id,
            repos=cve_data.get('repos', []),
            token=token,
            api_key=api_key,
            api_base=args.api_base,
            model=args.model,
        )

        llm_count = sum(1 for r in classified if r.get('classified_by') == 'llm')
        llm_calls += llm_count

        results[cve_id] = {
            'cve_id': cve_id,
            'repos': classified,
        }

        cat_counts = {}
        for r in classified:
            cat = r.get('category', '?')
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        if cat_counts:
            print(f'  Classification: {cat_counts}')
        if llm_count:
            print(f'  LLM calls: {llm_count}')

    # Build report
    report = build_report(results)

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f'\n{"="*60}')
    print(f'Report saved to {output_path}')
    print(f'Total CVEs: {report["stats"]["total_cves_searched"]}')
    print(f'CVEs with results: {report["stats"]["cves_with_results"]}')
    print(f'Total repos: {report["stats"]["total_repos"]}')
    print(f'By category: {report["stats"]["by_category"]}')
    print(f'Total LLM calls: {llm_calls}')


if __name__ == '__main__':
    main()
