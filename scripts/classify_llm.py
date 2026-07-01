"""
LLM-based classifier for GitHub repos.

Uses OpenAI-compatible API (GPT-4o-mini, DeepSeek, etc.)
to classify repos into 6 categories.
"""

import json
import os
import time
import urllib.request
import urllib.parse


CATEGORIES = {
    'exploit': 'Functional exploit code that can be directly executed against a target',
    'poc': 'Proof-of-concept demonstrating the vulnerability exists (may not be weaponized)',
    'detection': 'Tool for detecting, scanning, or checking if a system is vulnerable',
    'analysis': 'Technical writeup, analysis, or blog post (may include code snippets but not weaponized)',
    'unrelated': 'Repository not related to this CVE (mentioned CVE in description only)',
    'malware': 'Appears to be malicious code (ransomware, botnet, etc.)',
}

SYSTEM_PROMPT = f"""You are a security researcher classifying GitHub repositories related to CVE vulnerabilities.

Classify the repository into exactly ONE of these categories:
{chr(10).join(f'- {k}: {v}' for k, v in CATEGORIES.items())}

Output ONLY valid JSON: {{"category": "...", "confidence": 0.0-1.0, "reason": "..."}}

Confidence guidelines:
- 0.9-1.0: Clear, unambiguous classification
- 0.7-0.9: Strong signal but some uncertainty
- 0.5-0.7: Mixed signals, best guess
- Below 0.5: Very uncertain (still output your best guess)"""


def _build_opener():
    import os
    proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY') or os.environ.get('https_proxy')
    if proxy:
        handler = urllib.request.ProxyHandler({'https': proxy, 'http': proxy})
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()


_opener = None


def _get_opener():
    global _opener
    if _opener is None:
        _opener = _build_opener()
    return _opener


def classify_with_llm(cve_id: str, repo: dict, readme: str,
                       files: list[str], api_key: str,
                       api_base: str = 'https://api.openai.com/v1',
                       model: str = 'gpt-4o-mini') -> dict:
    """
    Classify a single repo using LLM.
    Returns {category, confidence, reason, classified_by: 'llm'}.
    """
    # Build user message
    file_list = ', '.join(files[:30])
    if len(files) > 30:
        file_list += f' (+{len(files) - 30} more)'

    user_msg = f"""Classify this GitHub repository related to {cve_id}.

Repo: {repo['owner']}/{repo['name']}
URL: {repo['url']}
Stars: {repo['stars']}  Language: {repo.get('language', 'N/A')}  Size: {repo.get('size', 0)}KB
Description: {repo.get('description', 'N/A')[:200]}

README (truncated):
{readme[:800]}

Files: {file_list}

Output JSON:"""

    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': user_msg},
        ],
        'temperature': 0.1,
        'max_tokens': 150,
    }).encode('utf-8')

    url = f'{api_base.rstrip("/")}/chat/completions'
    req = urllib.request.Request(url, data=payload, headers={
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}',
    })

    try:
        opener = _get_opener()
        with opener.open(req, timeout=30) as resp:
            data = json.loads(resp.read())
            content = data['choices'][0]['message']['content'].strip()
            # Parse JSON from response (handle markdown code blocks)
            if content.startswith('```'):
                content = content.split('```')[1]
                if content.startswith('json'):
                    content = content[4:]
            result = json.loads(content)
            result['classified_by'] = 'llm'
            return result
    except Exception as e:
        return {
            'category': 'unrelated',
            'confidence': 0.3,
            'reason': f'LLM classification failed: {e}',
            'classified_by': 'llm_error',
        }


def classify_batch(cve_id: str, repos: list[dict], api_key: str,
                    api_base: str = 'https://api.openai.com/v1',
                    model: str = 'gpt-4o-mini',
                    delay: float = 0.5) -> list[dict]:
    """
    Classify multiple repos for the same CVE.
    Each repo dict should have: owner, name, url, stars, metadata, readme, files.
    """
    results = []
    for repo in repos:
        result = classify_with_llm(
            cve_id=cve_id,
            repo=repo,
            readme=repo.get('readme', ''),
            files=repo.get('files', []),
            api_key=api_key,
            api_base=api_base,
            model=model,
        )
        results.append(result)
        if delay > 0:
            time.sleep(delay)
    return results
