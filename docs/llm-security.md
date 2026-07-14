# LLM / AI-application security

Codebases now embed LLM calls, agent frameworks, and model loading everywhere,
and that surface has its own vulnerability classes that generic SAST does not
cover. Argus ships a first-class scanner for them, the `llm` scanner, with
every finding mapped to the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/).

The scanner runs **only on files that actually touch an LLM/agent stack**
(OpenAI, Anthropic, LangChain, LlamaIndex, transformers, Ollama, etc.), so it
stays quiet on ordinary code and fast on large repositories.

## What it detects

| Rule | OWASP LLM | What it flags |
|------|-----------|---------------|
| `insecure-output-handling` | LLM02 | A model response flowing into `eval`/`exec`, `os.system`, `subprocess(shell=True)`, a SQL query, or unescaped HTML, detected with a single-file taint pass, and cleared when the output is parsed/validated first (`json.loads`, a schema, escaping). |
| `prompt-injection` | LLM01 | Untrusted input (request params, user messages) concatenated straight into a prompt or system message. |
| `secret-in-prompt` | LLM06 | An API key or credential interpolated into prompt text, where it is transmitted to the model provider and may be logged or echoed. |
| `trust-remote-code` | LLM05 | `trust_remote_code=True`, which executes arbitrary code shipped with a model at load time. |
| `torch-load-pickle` | LLM05 | `torch.load(...)` without `weights_only=True`, pickle code execution from an untrusted checkpoint. |
| `model-download-http` | LLM05 | Model/weights fetched over plaintext HTTP (tamperable in transit). |
| `agent-shell-tool` | LLM08 | An agent wired to a shell / code-execution tool (`ShellTool`, `PythonREPLTool`, …), so a prompt injection becomes command execution. |
| `unrestricted-tool-registration` | LLM08 | Flags like `allow_dangerous=True` that hand the model high-impact capability. |

## Usage

The scanner is on by default. To run only it:

```bash
argus scan ./my-ai-app --scanners llm
```

Findings carry the OWASP LLM category in both `owasp` and
`metadata.owasp_llm`, so you can filter or route them downstream.

## Scope and honesty

Like the regex/`patterns` tier, this is signature-plus-light-taint analysis,
not full data-flow: it favors precise, well-known signatures and marks
lower-confidence heuristics (like prompt-injection construction) as such.
Cross-file flows, a prompt built in one module and sent in another, are not
yet traced. Treat findings as high-value leads, and a clean result as "no known
LLM anti-patterns found," not a proof of safety.
