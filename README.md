# SubDrift

> Automated regex learning for DNS subdomain discovery.

This tool analyzes a list of **known subdomains** for a target, learns patterns from them using edit distance clustering and regex synthesis, and then **generates new candidate subdomains** that likely exist but haven't been discovered yet.

Instead of brute-forcing millions of random wordlist entries, subdrift is *smart* — it figures out the naming conventions of the target and generates candidates that match those patterns.

---

## How It Works

1. **Load** known subdomains from a file
2. **Compute** pairwise edit distances between all hostnames
3. **Cluster** similar hostnames into edit-distance closures (groups)
4. **Synthesize** a compact regex for each cluster using token-level analysis
5. **Generate** all hostnames that match each regex
6. **Output** the candidate list for DNS resolution/brute-force

> [!NOTE]
> This approach works best when the target uses systematic, pattern-based subdomain naming (e.g., `api-v1`, `api-v2`, `api-v3` → it will predict `api-v4`, `api-v5`, etc.). The more known subdomains you feed it, the better the results.

---

## Installation

```bash
git clone https://github.com/AliHzSec/subdrift.git
cd subdrift
pip install -r requirements.txt
```

---

## Usage

```
python3 main.py -d <domain> -i <input_file> [options]
```

### Arguments

| Flag | Long Flag | Required | Description |
|------|-----------|----------|-------------|
| `-d` | `--domain` | ✅ | Target root domain (e.g. `example.com`) |
| `-i` | `--input` | ✅ | Input file containing observed hostnames (one per line) |
| `-o` | `--output` | ❌ | Output file for generated candidates |
| `-sr` | `--save-rules` | ❌ | Save generated transformation rules to file |
| `-th` | `--threshold` | ❌ | Max number of synthetic words allowed per rule (default: `500`) |
| `-mr` | `--max-ratio` | ❌ | Max allowed ratio of synthetic to observed hostnames (default: `25.0`) |
| `-ml` | `--max-length` | ❌ | Max character length for a generated rule (default: `1000`) |
| `-dl` | `--dist-low` | ❌ | Minimum edit distance for grouping hostnames (default: `2`) |
| `-dh` | `--dist-high` | ❌ | Maximum edit distance for grouping hostnames (default: `10`) |
| `-s` | `--silent` | ❌ | Silent mode - suppress all log output (stdout only) |

---

## Examples

### Basic usage

```bash
python3 main.py -d example.com -i known_subs.txt
```

**Input file (`known_subs.txt`):**
```
api.example.com
api-v1.example.com
api-v2.example.com
dev.example.com
dev-v1.example.com
staging.example.com
```

**Output (stdout):**
```
api-v.example.com
api-v1.example.com
api-v2.example.com
api.example.com
api1.example.com
api2.example.com
dev-v.example.com
dev-v1.example.com
dev-v2.example.com
dev.example.com
dev1.example.com
dev2.example.com
staging-v.example.com
staging-v1.example.com
staging-v2.example.com
staging.example.com
staging1.example.com
staging2.example.com
...
```

> [!WARNING]
> Setting `-dh` too high (e.g. above `15`) or `-mr` too high may generate an extremely large number of low-quality candidates, significantly increasing noise and DNS query time.

---

## Recon Use Cases

### 1. Expand attack surface from passive recon
After collecting subdomains from sources like `subfinder`, `amass`, or `crt.sh`, feed them into subdrift to generate **new candidates** the passive tools would never find.

```bash
subfinder -d target.com -silent | tee known.txt
python3 main.py -d target.com -i known.txt -s | dnsx -silent
```

### 2. Discover internal/staging environments
Targets often follow patterns like `internal-api`, `internal-api-v2`, `dev-api`, `staging-api`. This tool picks up on these patterns and generates the full family.

> [!TIP]
> For best results, combine multiple passive recon sources before running subdrift. The more diverse your input subdomains are, the more accurate the learned patterns will be.

---

## Tuning Guide

| Goal | Recommended flags |
|------|-------------------|
| Fast, low-noise scan | `-dh 5 -mr 10.0 -th 300` |
| Balanced (default) | `-dh 10 -mr 25.0 -th 500` |
| Deep, aggressive scan | `-dh 15 -mr 50.0 -th 1000` |

> [!IMPORTANT]
> The quality of output heavily depends on the quality of input. Always deduplicate and validate your known subdomains before feeding them to subdrift. Malformed or irrelevant entries will produce noisy, low-quality rules.