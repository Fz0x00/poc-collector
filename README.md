# PoC Collector

GitHub API + LLM-based PoC/exploit intelligence collection for Chromium CVEs.

## What it does

1. **Searches GitHub** for repos related to each CVE ID
2. **Fetches** repo metadata, README, and file tree (3 API calls/repo)
3. **Rule-based pre-filter** classifies ~60% of repos without LLM
4. **LLM classification** for uncertain repos (6 categories)
5. **Outputs** structured JSON + Markdown report

## Categories

| Category | Meaning |
|----------|---------|
| `exploit` | Functional exploit code |
| `poc` | Proof-of-concept demonstrating the vulnerability |
| `detection` | Scanning/detection tool |
| `analysis` | Technical writeup (no weaponized code) |
| `unrelated` | Not related to this CVE |
| `malware` | Appears to be malicious |

## Usage

```bash
# Set environment variables
export GITHUB_TOKEN=ghp_...
export OPENAI_API_KEY=sk-...

# Run collection
python3 scripts/collect.py \
  --cve-file data/chromium-cves.json \
  --output data/poc-results.json \
  --model gpt-4o-mini

# Generate report
python3 scripts/report.py
```

## Cost estimate

~1,600 repos total, ~640 after rule filtering:
- GPT-4o-mini: ~$0.05/run
- DeepSeek-V3: ~$0.01/run
- Local model: $0

## Integration

Results feed into the [chromium-intel](https://github.com/Fz0x00/chromium-intel) dashboard:
- CVE detail pages show PoC availability + links + classification
- Evidence badges distinguish exploit/poc/detection
- PoC availability feeds into asset risk scoring
