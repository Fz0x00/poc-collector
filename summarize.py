#!/usr/bin/env python3
"""
repo-summarize — 两阶段 GitHub 仓库分析工具

Stage 1: 读 README，LLM 判断是否值得深入
Stage 2: clone 仓库，读源码，生成完整报告

用法:
  python3 summarize.py owner/repo
  python3 summarize.py owner/repo --lang zh
  python3 summarize.py owner/repo --json
  python3 summarize.py owner/repo --skip-stage1   # 跳过筛选，直接分析
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

# ─── HTTP helpers ──────────────────────────────────────────────

def _opener():
    proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY')
    if proxy:
        return urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy, 'http': proxy}))
    return urllib.request.build_opener()


def _github_get(url, token=None, timeout=15):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'repo-summarize/1.0'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(url, headers=headers)
    try:
        with _opener().open(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print('GitHub API rate limit — 设置 GITHUB_TOKEN', file=sys.stderr)
        elif e.code == 404:
            print(f'仓库不存在: {url}', file=sys.stderr)
        else:
            print(f'GitHub API 错误 {e.code}', file=sys.stderr)
        sys.exit(1)


def _llm_call(messages, api_key, api_base=None, model='gpt-4o-mini', max_tokens=500):
    api_base = api_base or os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')
    payload = json.dumps({
        'model': model,
        'messages': messages,
        'temperature': 0.2,
        'max_tokens': max_tokens,
    }).encode()
    req = urllib.request.Request(
        f'{api_base}/chat/completions',
        data=payload,
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'},
    )
    try:
        with _opener().open(req, timeout=60) as resp:
            data = json.loads(resp.read())
            msg = data['choices'][0]['message']
            content = (msg.get('content') or '').strip()
            reasoning = (msg.get('reasoning_content') or '').strip()

            # DeepSeek v4 推理模型：内容可能在 reasoning_content 中
            text = content or reasoning

            if not text:
                print(f'LLM 返回空内容', file=sys.stderr)
                return {'verdict': 'skip', 'reason': 'LLM returned empty response', 'brief_category': ''}

            # 尝试从 text 中提取 JSON
            # 先清理 markdown code block
            if '```' in text:
                parts = text.split('```')
                if len(parts) >= 2:
                    text = parts[1]
                    if text.startswith('json'):
                        text = text[4:]

            # 直接尝试解析
            try:
                return json.loads(text.strip())
            except json.JSONDecodeError:
                pass

            # 尝试找到第一个 { 到最后一个 }
            if '{' in text and '}' in text:
                start = text.index('{')
                end = text.rindex('}') + 1
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass

            print(f'LLM 返回非 JSON: {text[:300]}', file=sys.stderr)
            return {'verdict': 'skip', 'reason': 'LLM returned invalid JSON', 'brief_category': ''}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:500]
        print(f'LLM API 错误 {e.code}: {body}', file=sys.stderr)
        sys.exit(1)


def parse_repo(input_str):
    input_str = input_str.rstrip('/').replace('https://github.com/', '')
    parts = input_str.split('/')
    if len(parts) >= 2:
        return parts[0], parts[1]
    print(f'无法解析: {input_str}', file=sys.stderr)
    sys.exit(1)


# ─── Stage 1: README 快速筛选 ─────────────────────────────────

def fetch_readme(owner, name, token=None):
    """通过 GitHub API 获取 README（不 clone）。"""
    import base64
    try:
        r = _github_get(f'https://api.github.com/repos/{owner}/{name}/readme', token)
        if r.get('encoding') == 'base64':
            return base64.b64decode(r['content']).decode('utf-8', errors='replace')[:3000]
    except SystemExit:
        pass
    return ''


def fetch_meta(owner, name, token=None):
    """获取仓库元数据。"""
    r = _github_get(f'https://api.github.com/repos/{owner}/{name}', token)
    return {
        'stars': r.get('stargazers_count', 0),
        'forks': r.get('forks_count', 0),
        'language': r.get('language'),
        'description': r.get('description', ''),
        'size': r.get('size', 0),
    }


def stage1_screen(owner, name, meta, readme, api_key, model='gpt-4o-mini'):
    """Stage 1: 用 README 快速判断仓库是否值得深入分析。"""
    lang_instruction = '用中文回答。' if False else 'Output in English.'

    system_prompt = (
        "You are a security researcher screening GitHub repos.\n"
        "IMPORTANT: Output ONLY valid JSON, no thinking, no explanation, no markdown.\n"
        'Output format: {"verdict": "analyze|skip", "reason": "...", "brief_category": "poc|exploit|detection|analysis|unrelated|malware"}'
    )

    user_prompt = (
        f"Screen this repo:\n\n"
        f"Repo: {owner}/{name}\n"
        f"Stars: {meta.get('stars',0)}  Language: {meta.get('language','N/A')}  Size: {meta.get('size',0)}KB\n"
        f"Description: {meta.get('description','N/A')}\n\n"
        f"README:\n{readme[:2000]}\n\n"
        "Is this worth cloning and analyzing in detail? Output JSON:"
    )

    messages = [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': user_prompt},
    ]

    return _llm_call(messages, api_key, model=model, max_tokens=500)


# ─── Stage 2: Clone + 源码深度分析 ────────────────────────────

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
        print(f'  clone 失败: {r.stderr.strip()}', file=sys.stderr)
        return None
    return dest


def read_repo(repo_dir):
    """读取仓库内容：README + 代码文件。"""
    # README
    readme = ''
    for name in ['README.md', 'readme.md', 'README', 'Readme.md']:
        p = os.path.join(repo_dir, name)
        if os.path.isfile(p):
            with open(p, errors='replace') as f:
                readme = f.read()[:3000]
            break

    # 文件树 + 代码片段
    files = []
    code_snippets = []
    code_count = 0

    for root, dirs, fnames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
            'node_modules', '__pycache__', 'vendor', 'venv', '.git', 'dist', 'build')]

        rel_root = os.path.relpath(root, repo_dir)
        if rel_root == '.':
            rel_root = ''

        for fname in sorted(fnames):
            if fname.startswith('.'):
                continue
            rel_path = os.path.join(rel_root, fname) if rel_root else fname
            files.append(rel_path)

            ext = os.path.splitext(fname)[1].lower()
            if ext in CODE_EXTS and code_count < 20:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, errors='replace') as f:
                        content = f.read()[:5000]
                    code_snippets.append(f'--- {rel_path} ---\n{content}')
                    code_count += 1
                except Exception:
                    pass

    return readme, files, code_snippets


def stage2_analyze(owner, name, meta, readme, files, code_snippets, lang='zh', api_key=None, model='gpt-4o-mini'):
    """
    Stage 2: 深度分析，生成完整报告。
    """
    file_list = ', '.join(files[:40])
    if len(files) > 40:
        file_list += f' (+{len(files)-40} more)'

    code_block = '\n\n'.join(code_snippets) if code_snippets else '(no code files)'

    lang_instruction = '用中文回答。' if lang == 'zh' else 'Output in English.'

    system_prompt = (
        "You are a security researcher analyzing a CVE-related GitHub repository in detail.\n\n"
        + lang_instruction + "\n"
        "Output JSON:\n"
        "{\n"
        '  "category": "exploit|poc|detection|analysis|unrelated|malware",\n'
        '  "title": "one-line description",\n'
        '  "summary": ["detailed point 1", "detailed point 2", "detailed point 3", "..."],\n'
        '  "technical_details": "how the vulnerability is triggered/exploited, what code does",\n'
        '  "affected_component": "what software/component is affected",\n'
        '  "severity_assessment": "critical|high|medium|low|unknown",\n'
        '  "tags": ["tag1", "tag2"],\n'
        '  "usage_notes": "how to use this PoC/exploit (if applicable)",\n'
        '  "confidence": 0.0-1.0\n'
        "}"
    )

    user_prompt = (
        f"Analyze this repository in depth:\n\n"
        f"Repo: {owner}/{name}\n"
        f"Stars: {meta.get('stars',0)}  Language: {meta.get('language','N/A')}  Size: {meta.get('size',0)}KB\n"
        f"Description: {meta.get('description','N/A')}\n\n"
        f"README:\n{readme}\n\n"
        f"Files ({len(files)}): {file_list}\n\n"
        f"Source code:\n{code_block[:16000]}\n\n"
        "Generate a complete analysis report. Output JSON:"
    )

    messages = [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': user_prompt},
    ]

    return _llm_call(messages, api_key, model=model, max_tokens=1500)


# ─── 主流程 ────────────────────────────────────────────────────

def analyze(owner, name, api_key, token=None, lang='zh', model='gpt-4o-mini',
            skip_stage1=False, api_base=None):
    """
    完整两阶段分析流程。
    返回分析结果 dict。
    """
    # 获取元数据
    meta = fetch_meta(owner, name, token)
    desc = (meta.get("description") or "")[:60]
    print(f'  ⭐ {meta["stars"]}  🔤 {meta["language"]}  📝 {desc}', file=sys.stderr)

    # Stage 1: README 筛选
    if not skip_stage1:
        print('  [Stage 1] README 筛选...', file=sys.stderr)
        readme = fetch_readme(owner, name, token)
        if not readme:
            print('  ⚠ 无法获取 README，跳过', file=sys.stderr)
            return {'verdict': 'skip', 'reason': 'no readme'}

        screen = stage1_screen(owner, name, meta, readme, api_key, model=model)
        verdict = screen.get('verdict', 'skip')

        if verdict == 'skip':
            print(f'  ⏭ 跳过: {screen.get("reason","")}', file=sys.stderr)
            return {
                'repo': f'{owner}/{name}',
                **meta,
                'verdict': 'skip',
                'reason': screen.get('reason', ''),
                'brief_category': screen.get('brief_category', ''),
            }

        print(f'  ✓ 值得深入 ({screen.get("brief_category","")})', file=sys.stderr)
    else:
        readme = fetch_readme(owner, name, token)

    # Stage 2: Clone + 深度分析
    print('  [Stage 2] Clone + 源码分析...', file=sys.stderr)
    tmpdir = tempfile.mkdtemp(prefix='repo-')
    try:
        repo_dir = git_clone(owner, name, token, tmpdir)
        if not repo_dir:
            return {'repo': f'{owner}/{name}', **meta, 'verdict': 'error', 'reason': 'clone failed'}

        local_readme, files, code_snippets = read_repo(repo_dir)
        # 用本地 README 替代 API 获取的（更完整）
        if local_readme:
            readme = local_readme

        print(f'  📁 {len(files)} files, {len(code_snippets)} code snippets', file=sys.stderr)

        report = stage2_analyze(owner, name, meta, readme, files, code_snippets,
                                lang, api_key, model)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return {
        'repo': f'{owner}/{name}',
        **meta,
        'verdict': 'analyzed',
        **report,
    }


def main():
    parser = argparse.ArgumentParser(description='两阶段 GitHub 仓库分析工具')
    parser.add_argument('repo', help='owner/repo 或 GitHub URL')
    parser.add_argument('--lang', '-l', default='zh', choices=['en', 'zh'], help='输出语言')
    parser.add_argument('--model', '-m', default='gpt-4o-mini')
    parser.add_argument('--json', '-j', action='store_true', help='输出原始 JSON')
    parser.add_argument('--skip-stage1', action='store_true', help='跳过 README 筛选，直接分析')
    args = parser.parse_args()

    token = os.environ.get('GITHUB_TOKEN')
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print('需要设置 OPENAI_API_KEY', file=sys.stderr)
        sys.exit(1)

    owner, name = parse_repo(args.repo)
    print(f'分析 {owner}/{name}...', file=sys.stderr)

    result = analyze(owner, name, api_key, token, args.lang, args.model, args.skip_stage1)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if result.get('verdict') == 'skip':
            print(f'\n⏭ {owner}/{name} — 跳过: {result.get("reason","")}')
        else:
            print(f'\n## {owner}/{name}')
            cat = result.get('category', '?')
            title = result.get('title', '')
            conf = result.get('confidence', 0)
            print(f'  类别: {cat} | 置信度: {conf:.0%}')
            if title:
                print(f'  {title}')
            print()
            for point in result.get('summary', []):
                print(f'  • {point}')
            if result.get('technical_details'):
                print(f'\n  技术细节: {result["technical_details"]}')
            if result.get('usage_notes'):
                print(f'  使用说明: {result["usage_notes"]}')
            tags = result.get('tags', [])
            if tags:
                print(f'  标签: {", ".join(tags)}')


if __name__ == '__main__':
    main()
