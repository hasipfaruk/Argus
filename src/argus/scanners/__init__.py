"""Built-in scanners.

Importing this package registers the built-in scanners with the global registry.
Each scanner is small and self-contained; they are the reference implementations
that the plugin guide points contributors at.
"""

from argus.scanners import (  # noqa: F401
    ast_js,
    ast_python,
    ast_python_interproc,
    dependencies,
    iac,
    llm,
    patterns,
    secrets,
)

__all__ = ["ast_js", "ast_python", "ast_python_interproc", "dependencies", "iac",
           "llm", "patterns", "secrets"]
