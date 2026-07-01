#!/usr/bin/env python3
"""
repo-summarize — 用 LLM 总结 GitHub 仓库

通过 git clone 浅克隆仓库到本地，读取实际代码后用 LLM 分析。

用法:
  python3 summarize.py owner/repo
  python3 summarize.py https://github.com/owner/repo
  python3 summarize.py owner/repo --lang zh
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
import urllib.error


CODE_EXTS = {
    '.py', '.c', '.cpp', '.cc', '.h', '.hpp', '.js', '.ts', '.go', '.rs',
    '.java', '.rb', '.php', '.cs', '.swift', '.kt', '.sh', '.bash',
    '.html', '.jsx', '.tsx', '.vue', '.svelte',
}


def _opener():
    proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY')
    if proxy:
        return urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy, 'http': proxy}))
    return urllib.request.build_opener()


def parse_repo(input_str):
    input_str = input_str.rstrip('/').replace('https://github.com/', '')
    parts = input_str.split('/')
    if len(parts) >= 2:
        return parts[0], parts[1]
    print(f'无法解析: {input_str}', file=sys.stderr)
    sys.exit(1)


def git_clone(owner, name, token=None, tmpdir=None):
    url = f'https://github.com/{owner}/{name}.git'
    if token:
        url = f'https://{token}@github.com/{owner}/{name}.git'
    dest = os.path.join(tmpdir, name)
    r = subprocess.run(
        ['git', 'clone', '--depth', '1', '--quiet', url, dest],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        print(f'clone 失败: {r.stderr.strip()}', file=sys.stderr)
        sys.exit(1)
    return dest


def walk_repo(repo_dir):
    """Walk repo directory, return (readme, file_tree, code_snippets)."""
    readme = ''
    readme_path = os.path.join(repo_dir, 'README.md')
    if os.path.isfile(readme_path):
        with open(readme_path, errors='replace') as f:
            readme = f.read()[:2000]

    # Also try README (no extension)
    if not readme:
        for name in ['readme.md', 'readme', 'README', 'Readme.md']:
            p = os.path.join(repo_dir, name)
            if os.path.isfile(p):
                with open(p, errors='replace') as f:
                    readme = f.read()[:2000]
                break

    files = []
    code_snippets = []
    code_count = 0

    for root, dirs, fnames in os.walk(repo_dir):
        # Skip hidden dirs and node_modules
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', 'vendor', 'venv')]

        rel_root = os.path.relpath(root, repo_dir)
        if rel_root == '.':
            rel_root = ''

        for fname in sorted(fnames):
            if fname.startswith('.'):
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.join(rel_root, fname) if rel_root else fname
            files.append(rel_path)

            ext = os.path.splitext(fname)[1].lower()
            if ext in CODE_EXTS and code_count < 5:
                try:
                    with open(fpath, errors='replace') as f:
                        content = f.read()[:800]
                    code_snippets.append(f'--- {rel_path} ---\n{content}')
                    code_count += 1
                except Exception:
                    pass

    return readme, files, code_snippets


def build_meta(repo_dir):
    """Extract basic metadata from repo dir."""
    lang_counts = {}
    total_size = 0
    for root, dirs, fnames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for fname in fnames:
            fpath = os.path.join(root, fname)
            try:
                total_size += os.path.getsize(fpath)
            except OSError:
                pass
            ext = os.path.splitext(fname)[1].lower()
            if ext in CODE_EXTS:
                lang_counts[ext] = lang_counts.get(ext, 0) + 1

    top_lang = max(lang_counts, key=lang_counts.get) if lang_counts else 'N/A'
    ext_to_lang = {
        '.py': 'Python', '.c': 'C', '.cpp': 'C++', '.h': 'C/C++',
        '.js': 'JavaScript', '.ts': 'TypeScript', '.go': 'Go', '.rs': 'Rust',
        '.java': 'Java', '.rb': 'Ruby', '.php': 'PHP', '.cs': 'C#',
    }
    return {
        'language': ext_to_lang.get(top_lang, top_lang),
        'size_kb': total_size // 1024,
    }


def summarize(owner, name, meta, readme, files, code_snippets, lang='en', api_key=None, model='gpt-4o-mini'):
    file_list = ', '.join(files[:40])
    if len(files) > 40:
        file_list += f' (+{len(files)-40} more)'

    code_block = '\n\n'.join(code_snippets) if code_snippets else '(no code files)'

    lang_instruction = '用中文回答。' if lang == 'zh' else 'Output in English.'

    prompt = f"""Analyze this GitHub repository and provide a concise summary.

Repo: {owner}/{name}
Language: {meta.get('language','N/A')}  Size: {meta.get('size_kb',0)}KB
Files ({len(files)}): {file_list}

README:
{readme[:1200]}

Key source code:
{code_block[:2000]}

{lang_instruction}
Output JSON:
{{
  "summary": ["point1", "point2", "point3"],
  "tags": ["tag1", "tag2"],
  "type": "poc|exploit|tool|library|analysis|other"
}}"""

    api_base = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')
    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'You are a code analyst. Be concise and accurate.'},
            {'role': 'user', 'content': prompt},
        ],
        'temperature': 0.2,
        'max_tokens': 400,
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

    tmpdir = tempfile.mkdtemp(prefix='repo-')
    try:
        print(f'Clone {owner}/{name}...', file=sys.stderr)
        repo_dir = git_clone(owner, name, token, tmpdir)

        meta = build_meta(repo_dir)
        readme, files, code_snippets = walk_repo(repo_dir)

        print(f'📁 {meta["language"]}  💾 {meta["size_kb"]}KB  📄 {len(files)} files', file=sys.stderr)

        result = summarize(owner, name, meta, readme, files, code_snippets,
                          args.lang, api_key, args.model)

        if args.json:
            out = {'repo': f'{owner}/{name}', 'stars': '-', **meta, **result}
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print(f'\n## {owner}/{name}')
            for point in result.get('summary', []):
                print(f'  • {point}')
            tags = result.get('tags', [])
            repo_type = result.get('type', '')
            if repo_type:
                print(f'  Type: {repo_type}')
            if tags:
                print(f'  Tags: {", ".join(tags)}')
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    main()
