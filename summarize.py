#!/usr/bin/env python3
"""
repo-summarize — 用 LLM 总结 GitHub 仓库

用法:
  python3 summarize.py owner/repo
  python3 summarize.py https://github.com/owner/repo
  python3 summarize.py owner/repo --lang zh
"""

import argparse
import json
import os
import sys
import base64
import urllib.request
import urllib.parse
import urllib.error


def _opener():
    proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY')
    if proxy:
        return urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy, 'http': proxy}))
    return urllib.request.build_opener()


def _get(url, token=None, timeout=15):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'repo-summarize/1.0'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(url, headers=headers)
    try:
        with _opener().open(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print('GitHub API rate limit — 设置 GITHUB_TOKEN 可提高到 5000 req/h', file=sys.stderr)
        elif e.code == 404:
            print(f'仓库不存在: {url}', file=sys.stderr)
        else:
            print(f'GitHub API 错误 {e.code}: {e.read().decode()[:200]}', file=sys.stderr)
        sys.exit(1)


def parse_repo(input_str):
    input_str = input_str.rstrip('/').replace('https://github.com/', '')
    parts = input_str.split('/')
    if len(parts) >= 2:
        return parts[0], parts[1]
    print(f'无法解析: {input_str}', file=sys.stderr)
    sys.exit(1)


def fetch(owner, name, token=None):
    meta = _get(f'https://api.github.com/repos/{owner}/{name}', token)

    readme = ''
    try:
        r = _get(f'https://api.github.com/repos/{owner}/{name}/readme', token)
        if r.get('encoding') == 'base64':
            readme = base64.b64decode(r['content']).decode('utf-8', errors='replace')[:1500]
    except Exception:
        pass

    files = []
    try:
        t = _get(f'https://api.github.com/repos/{owner}/{name}/git/trees/{meta.get("default_branch","main")}?recursive=1', token)
        files = [i['path'] for i in t.get('tree', []) if i.get('type') == 'blob'][:50]
    except Exception:
        pass

    return meta, readme, files


def summarize(owner, name, meta, readme, files, lang='en', api_key=None, model='gpt-4o-mini'):
    file_list = ', '.join(files[:30])
    if len(files) > 30:
        file_list += f' (+{len(files)-30} more)'

    lang_instruction = 'Output in Chinese.' if lang == 'zh' else 'Output in English.'

    prompt = f"""Summarize this GitHub repo in 3-5 bullet points.

Repo: {owner}/{name}
Stars: {meta.get('stargazers_count',0)}  Language: {meta.get('language','N/A')}  Size: {meta.get('size',0)}KB
Description: {meta.get('description','N/A')}

README:
{readme[:1000]}

Files: {file_list}

{lang_instruction}
Output JSON: {{"summary": ["point1", "point2", ...], "tags": ["tag1", "tag2"]}}"""

    api_base = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')
    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'You are a code analyst. Be concise.'},
            {'role': 'user', 'content': prompt},
        ],
        'temperature': 0.2,
        'max_tokens': 300,
    }).encode()

    req = urllib.request.Request(
        f'{api_base}/chat/completions',
        data=payload,
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'},
    )
    with _opener().open(req, timeout=30) as resp:
        data = json.loads(resp.read())
        content = data['choices'][0]['message']['content'].strip()
        if content.startswith('```'):
            content = content.split('```')[1]
            if content.startswith('json'):
                content = content[4:]
        return json.loads(content)


def main():
    parser = argparse.ArgumentParser(description='用 LLM 总结 GitHub 仓库')
    parser.add_argument('repo', help='owner/repo 或 GitHub URL')
    parser.add_argument('--lang', '-l', default='en', choices=['en', 'zh'], help='输出语言')
    parser.add_argument('--model', '-m', default='gpt-4o-mini')
    parser.add_argument('--json', '-j', action='store_true', help='输出原始 JSON')
    args = parser.parse_args()

    token = os.environ.get('GITHUB_TOKEN')
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print('需要设置 OPENAI_API_KEY', file=sys.stderr)
        sys.exit(1)

    owner, name = parse_repo(args.repo)
    print(f'获取 {owner}/{name}...', file=sys.stderr)

    meta, readme, files = fetch(owner, name, token)

    stars = meta.get('stargazers_count', 0)
    lang = meta.get('language', 'N/A')
    desc = meta.get('description', 'N/A') or 'N/A'
    print(f'⭐ {stars}  🔤 {lang}  📝 {desc}', file=sys.stderr)

    result = summarize(owner, name, meta, readme, files, args.lang, api_key, args.model)

    if args.json:
        print(json.dumps({'repo': f'{owner}/{name}', 'stars': stars, **result}, ensure_ascii=False, indent=2))
    else:
        print(f'\n## {owner}/{name}')
        for point in result.get('summary', []):
            print(f'  • {point}')
        tags = result.get('tags', [])
        if tags:
            print(f'  Tags: {", ".join(tags)}')


if __name__ == '__main__':
    main()
