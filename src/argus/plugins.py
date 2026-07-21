"""Built-in plugin registration.

Referenced by the ``argus.plugins`` entry point in ``pyproject.toml``. Importing
these packages is what registers the built-in scanners, reporters, and AI
providers with the global registry. Third-party plugins do the same from their
own ``register`` callable.
"""

from __future__ import annotations


def register_builtins() -> None:
    # Imports have registration side effects via the @scanner/@reporter/@ai_provider
    # decorators, so importing the packages is all that's required.
    from argus import scanners  # noqa: F401  (registers scanners)
    from argus.ai import (  # noqa: F401  (registers AI providers)
        anthropic_provider,
        heuristic,
        ollama_provider,
        openai_provider,
    )
    from argus.reporting import (  # noqa: F401  (registers reporters)
        badge,
        gitlab,
        html,
        json_reporter,
        markdown,
        sarif,
        vex,
    )
