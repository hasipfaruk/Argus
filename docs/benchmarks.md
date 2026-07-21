# Benchmarks & accuracy

A scanner's most important number is how accurate it is, and the most honest thing
a young scanner can do is publish that number with its methodology, and republish
it when it gets worse. Argus AppSec measures accuracy two ways.

## Labeled corpus (precision and recall)

A small, fully labeled corpus ships in the repo so the numbers are reproducible on
any machine with one command and no downloads:

```bash
python benchmarks/accuracy.py
```

Every case is a single file that is either **vulnerable** (Argus must raise at
least one actionable finding) or **safe** (Argus must raise none). From that:

- **Recall** = caught vulnerable cases / all vulnerable cases (did we miss a bug?)
- **Precision** = caught / (caught + findings on safe cases) (did we cry wolf?)

Current results:

| Domain | Recall | Precision | Vulnerable cases | False positives |
| --- | --- | --- | --- | --- |
| secrets | 100% | 100% | 1 | 0 |
| sast | 100% | 100% | 3 | 0 |
| taint | 100% | 100% | 1 | 0 |
| iac | 100% | 100% | 1 | 0 |
| llm | 100% | 100% | 6 | 0 |
| **overall** | **100%** | **100%** | **12** | **0** |

!!! warning "Read this number honestly"
    This is a **small sanity-and-regression corpus** (12 vulnerable, 11 safe cases),
    not a claim of 100% real-world accuracy. 100% here means Argus classifies
    every case in this set correctly, and the run **exits non-zero if it does
    not**, so a regression fails CI. Real-world precision/recall across large
    codebases is lower and is what the public-corpus work below is for.

The **llm** rows are worth calling out: there is no standard public benchmark for
LLM/AI-application vulnerability classes (prompt injection, insecure model-output
handling, unsafe model loading, secrets in prompts, excessive agency). This
labeled set covers OWASP LLM01/02/05/06/08 with a vulnerable and a safe case each,
so the accuracy claim in Argus's strongest and least-crowded domain is measurable
and reproducible rather than asserted.

This corpus already earned its keep: building it surfaced two real bugs, both now
fixed and covered by regression tests:

- A false **negative**: `subprocess(..., shell=True)` was being dropped by the
  engine whenever the AST taint tier ran, because that tier does not model a
  taint-independent smell. Command-execution findings now survive.
- A false **positive**: a properly parameterized query
  `execute("... %s", (uid,))` was flagged as SQL injection because a tainted value
  in the bound-parameters argument counted. Bound parameters are now recognized as
  the safe form.

## Public reference apps (finding inventory)

The larger harness scans real, known-vulnerable applications:

```bash
python benchmarks/run_benchmarks.py            # all available corpora
python benchmarks/run_benchmarks.py juice-shop # just one
```

It publishes a **finding inventory** (counts by scanner and severity, plus scan
time) for OWASP Juice Shop, DVWA, WebGoat, and (with a manual download) NIST
SARD/Juliet. An inventory is not precision/recall, it needs a ground-truth
mapping per corpus, which is tracked as a `ground_truth` hook and where
contributions are welcome, but it shows coverage shape and catches per-release
regressions in what Argus finds and how fast.

## Methodology and honesty notes

- Runs are deterministic and offline (`--no-ai`, caching disabled) so numbers are
  comparable across machines.
- Numbers that get worse are published anyway. A benchmark that only ever improves
  is marketing, not measurement.
- The labeled corpus is intentionally small and unambiguous. Growing it (more
  languages, more classes, adversarial safe cases) directly improves the quality
  signal, and pull requests that add labeled cases are among the most valuable
  contributions to the project.
