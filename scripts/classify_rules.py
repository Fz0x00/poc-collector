"""
Rule-based pre-filter for GitHub repos.

Classifies repos directly without LLM when confidence is high.
Returns (category, confidence, reason) or None if uncertain.
"""

import re

# Patterns for code files by extension
CODE_EXTENSIONS = {
    '.py', '.c', '.cpp', '.cc', '.h', '.hpp', '.js', '.ts', '.go', '.rs',
    '.java', '.rb', '.php', '.cs', '.swift', '.kt', '.sh', '.bash', '.ps1',
    '.html', '.css', '.jsx', '.tsx', '.vue', '.svelte',
}

# PoC/exploit keywords in README
POC_KEYWORDS = re.compile(
    r'\b(poc|proof.of.concept|exploit|trigger|vulnerab|attack|payload|'
    r'heap.spray|buffer.overflow|use.after.free|integer.overflow|'
    r'out.of.bounds|arbitrary.write|code.execution|remote.code|'
    r'rce|cmdi|injection|overflow|underflow|crash|segfault|core.dump)\b',
    re.IGNORECASE,
)

# Detection/scanner keywords
DETECTION_KEYWORDS = re.compile(
    r'\b(detect|scanner|scanning|check|checker|audit|monitor|scan|'
    r'signature|yara|sigma|snort|suricata|wazuh|nessus|qualys|openvas)\b',
    re.IGNORECASE,
)

# Analysis/writeup keywords (no code)
ANALYSIS_KEYWORDS = re.compile(
    r'\b(writeup|write.up|analysis|write-up|blog|post|explanation|'
    r'deep.dive|breakdown|root.cause|patch.diff|commit.diff|advisory)\b',
    re.IGNORECASE,
)

# Unrelated keywords
UNRELATED_KEYWORDS = re.compile(
    r'\b(awesome|list|collection|resources|learning|tutorial|course|'
    r'ctf|challenge|writeup.*ctf|training|bootcamp|certification)\b',
    re.IGNORECASE,
)

# Malware indicators
MALWARE_KEYWORDS = re.compile(
    r'\b(malware|ransomware|botnet|c2|command.and.control|backdoor|'
    r'trojan|rat|infostealer|stealer|loader|dropper|payload.*drop)\b',
    re.IGNORECASE,
)


def _has_code_files(files: list[str]) -> bool:
    """Check if repo contains source code files."""
    for f in files:
        ext = '.' + f.rsplit('.', 1)[-1].lower() if '.' in f else ''
        if ext in CODE_EXTENSIONS:
            return True
    return False


def _count_code_files(files: list[str]) -> int:
    """Count source code files."""
    count = 0
    for f in files:
        ext = '.' + f.rsplit('.', 1)[-1].lower() if '.' in f else ''
        if ext in CODE_EXTENSIONS:
            count += 1
    return count


def classify_by_rules(owner: str, name: str, stars: int, description: str,
                      readme: str, files: list[str]) -> tuple[str, float, str] | None:
    """
    Try to classify a repo using rules only.
    Returns (category, confidence, reason) or None if uncertain.
    """
    text = f'{description} {readme}'
    cve_in_name = 'cve-' in name.lower()

    # Rule 1: stars > 100 + CVE in name → high confidence poc/exploit
    if stars > 100 and cve_in_name:
        if POC_KEYWORDS.search(text):
            return ('poc', 0.85, f'Hight stars ({stars}) + CVE name + PoC keywords')
        return ('poc', 0.75, f'High stars ({stars}) + CVE in repo name')

    # Rule 2: No code files at all → likely unrelated or analysis
    if not _has_code_files(files):
        if ANALYSIS_KEYWORDS.search(text):
            return ('analysis', 0.80, 'No code files + analysis keywords in README')
        if POC_KEYWORDS.search(text):
            # Has PoC keywords but no code - might be a writeup
            return ('analysis', 0.70, 'PoC keywords but no code files')
        return ('unrelated', 0.75, 'No source code files found')

    # Rule 3: README explicitly says it's a PoC
    readme_lower = readme.lower()
    if re.search(r'\bthis\s+is\s+(a\s+)?(poc|proof.of.concept|exploit)\b', readme_lower):
        if _count_code_files(files) >= 1:
            return ('poc', 0.90, 'Explicitly claims to be PoC + has code')

    # Rule 4: Detection tool patterns
    if DETECTION_KEYWORDS.search(text) and not POC_KEYWORDS.search(text):
        if 'checker' in name.lower() or 'scanner' in name.lower() or 'detect' in name.lower():
            return ('detection', 0.85, 'Detection keywords + scanner-like name')

    # Rule 5: Unrelated collection/awesome list
    if UNRELATED_KEYWORDS.search(text) and not POC_KEYWORDS.search(text):
        if 'awesome' in name.lower() or 'list' in name.lower() or 'resource' in name.lower():
            return ('unrelated', 0.80, 'Collection/list pattern, no PoC keywords')

    # Rule 6: Malware indicators
    if MALWARE_KEYWORDS.search(text) and not POC_KEYWORDS.search(text):
        return ('malware', 0.75, 'Malware-related keywords found')

    # Rule 7: Very small repo with CVE in name and some code
    if cve_in_name and stars < 5 and _count_code_files(files) <= 2:
        if POC_KEYWORDS.search(text):
            return ('poc', 0.65, 'Small repo, CVE name, PoC keywords, minimal code')
        return ('unrelated', 0.60, 'Very small repo, minimal code, no clear PoC signal')

    # Uncertain - defer to LLM
    return None
