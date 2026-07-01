"""Tests for rule-based classifier."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'scripts'))

from classify_rules import classify_by_rules


def test_poc_explicit_readme():
    repo = {
        'owner': 'test', 'name': 'CVE-2023-4863-poc',
        'stars': 50, 'description': 'PoC for libwebp vulnerability',
        'readme': 'This is a poc for CVE-2023-4863. It creates a malformed WebP file.',
        'files': ['README.md', 'poc.py', 'craft.c'],
    }
    result = classify_by_rules(**repo)
    assert result is not None, 'Should classify explicit PoC'
    cat, conf, reason = result
    assert cat == 'poc'
    assert conf >= 0.8


def test_high_star_cve_name():
    repo = {
        'owner': 'test', 'name': 'CVE-2023-4863',
        'stars': 500, 'description': 'WebP vulnerability exploit',
        'readme': 'Some readme',
        'files': ['README.md', 'exploit.py'],
    }
    result = classify_by_rules(**repo)
    assert result is not None
    cat, conf, reason = result
    assert cat == 'poc'
    assert conf >= 0.75


def test_no_code_files():
    repo = {
        'owner': 'test', 'name': 'awesome-cves',
        'stars': 10, 'description': 'A list of CVE resources',
        'readme': 'Collection of useful CVE resources and links',
        'files': ['README.md', 'LICENSE'],
    }
    result = classify_by_rules(**repo)
    assert result is not None
    cat, conf, reason = result
    assert cat == 'unrelated'


def test_detection_tool():
    repo = {
        'owner': 'test', 'name': 'libwebp-checker',
        'stars': 20, 'description': 'Detect if your system is vulnerable to CVE-2023-4863',
        'readme': 'This scanner checks for vulnerable libwebp versions',
        'files': ['README.md', 'check.py'],
    }
    result = classify_by_rules(**repo)
    assert result is not None
    cat, conf, reason = result
    assert cat == 'detection'


def test_uncertain_returns_none():
    repo = {
        'owner': 'test', 'name': 'some-random-repo',
        'stars': 5, 'description': 'A repo about webp',
        'readme': 'This repo does webp stuff',
        'files': ['README.md', 'main.py', 'utils.py', 'test.py'],
    }
    result = classify_by_rules(**repo)
    assert result is None, 'Should return None for uncertain repos'


def test_awesome_list():
    repo = {
        'owner': 'test', 'name': 'awesome-web-security',
        'stars': 200, 'description': 'Awesome list of web security resources',
        'readme': 'A curated list of web security resources including CVEs, tools, and writeups',
        'files': ['README.md', 'CONTRIBUTING.md'],
    }
    result = classify_by_rules(**repo)
    assert result is not None
    cat, conf, reason = result
    assert cat == 'unrelated'


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f'  PASS: {test.__name__}')
            passed += 1
        except AssertionError as e:
            print(f'  FAIL: {test.__name__}: {e}')
            failed += 1
        except Exception as e:
            print(f'  ERROR: {test.__name__}: {e}')
            failed += 1
    print(f'\n{passed} passed, {failed} failed')
