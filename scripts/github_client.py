"""
GitHub API client for searching CVE-related repositories and fetching repo data.

Handles:
- Search API: find repos matching CVE IDs
- Repo API: fetch metadata, README, file tree
- Rate limiting and pagination
- Proxy support
"""

import json
import time
import base64
import urllib.request
import urllib.parse
from typing import Optional


SEARCH_DELAY = 2  # seconds between search requests (30 req/min for authenticated)
REPO_DELAY = 0.5  # seconds between repo detail requests (5000/hr)
MAX_RETRIES = 3


def _build_opener():
    """Build urllib opener with proxy support."""
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


def _headers(token: Optional[str] = None) -> dict:
    h = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'poc-collector/1.0',
    }
    if token:
        h['Authorization'] = f'Bearer {token}'
    return h


def _request(url: str, token: Optional[str] = None, timeout: int = 30) -> dict:
    """Make a GET request with retries and rate-limit handling."""
    opener = _get_opener()
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers=_headers(token))
            with opener.open(req, timeout=timeout) as resp:
                remaining = resp.headers.get('X-RateLimit-Remaining')
                if remaining is not None and int(remaining) < 5:
                    reset = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
                    wait = max(reset - int(time.time()), 1)
                    print(f'  Rate limit low ({remaining}), sleeping {wait}s...')
                    time.sleep(wait)
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # Rate limited
                reset = e.headers.get('X-RateLimit-Reset') if hasattr(e, 'headers') else None
                if reset:
                    wait = max(int(reset) - int(time.time()), 10)
                    print(f'  Rate limited, sleeping {wait}s...')
                    time.sleep(wait)
                    continue
            if e.code == 422:
                print(f'  Validation error: {e.read().decode()[:200]}')
                return {}
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** (attempt + 1))
                continue
            raise
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** (attempt + 1))
                continue
            raise
    return {}


def search_repos_for_cve(cve_id: str, token: Optional[str] = None, max_results: int = 30) -> list[dict]:
    """
    Search GitHub for repos related to a CVE ID.
    Returns list of {owner, name, url, stars, forks, language, description, size, topics, created_at, pushed_at}.
    """
    query = f'{cve_id} in:name,description'
    params = urllib.parse.urlencode({
        'q': query,
        'sort': 'stars',
        'order': 'desc',
        'per_page': min(max_results, 30),
    })
    url = f'https://api.github.com/search/repositories?{params}'
    data = _request(url, token)

    results = []
    for item in data.get('items', []):
        if item.get('fork'):
            continue
        results.append({
            'owner': item['owner']['login'],
            'name': item['name'],
            'url': item['html_url'],
            'stars': item.get('stargazers_count', 0),
            'forks': item.get('forks_count', 0),
            'language': item.get('language'),
            'description': item.get('description', ''),
            'size': item.get('size', 0),
            'topics': item.get('topics', []),
            'created_at': item.get('created_at'),
            'pushed_at': item.get('pushed_at'),
            'default_branch': item.get('default_branch', 'main'),
        })

    time.sleep(SEARCH_DELAY)
    return results


def fetch_repo_metadata(owner: str, name: str, token: Optional[str] = None) -> dict:
    """Fetch repo metadata (stars, lang, description)."""
    url = f'https://api.github.com/repos/{owner}/{name}'
    data = _request(url, token)
    time.sleep(REPO_DELAY)
    return {
        'stars': data.get('stargazers_count', 0),
        'forks': data.get('forks_count', 0),
        'language': data.get('language'),
        'description': data.get('description', ''),
        'size': data.get('size', 0),
        'topics': data.get('topics', []),
        'default_branch': data.get('default_branch', 'main'),
    }


def fetch_readme(owner: str, name: str, token: Optional[str] = None) -> str:
    """Fetch decoded README content (truncated to 2000 chars)."""
    url = f'https://api.github.com/repos/{owner}/{name}/readme'
    data = _request(url, token)
    time.sleep(REPO_DELAY)

    content = data.get('content', '')
    encoding = data.get('encoding', '')
    if encoding == 'base64' and content:
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='replace')
            return decoded[:2000]
        except Exception:
            return ''
    return ''


def fetch_file_tree(owner: str, name: str, sha: str = 'HEAD',
                    token: Optional[str] = None) -> list[str]:
    """Fetch recursive file tree, return list of file paths."""
    url = f'https://api.github.com/repos/{owner}/{name}/git/trees/{sha}?recursive=1'
    data = _request(url, token)
    time.sleep(REPO_DELAY)

    paths = []
    for item in data.get('tree', []):
        if item.get('type') == 'blob':
            paths.append(item['path'])
    return paths


def fetch_repo_full(owner: str, name: str, token: Optional[str] = None) -> dict:
    """
    Fetch all data for a repo: metadata + README + file tree.
    Returns {metadata, readme, files}.
    """
    meta = fetch_repo_metadata(owner, name, token)
    readme = fetch_readme(owner, name, token)
    files = fetch_file_tree(owner, name, meta.get('default_branch', 'main'), token)
    return {
        'metadata': meta,
        'readme': readme,
        'files': files,
    }
