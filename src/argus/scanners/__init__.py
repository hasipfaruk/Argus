"""Built-in scanners.

Importing this package registers the built-in scanners with the global registry.
Each scanner is small and self-contained; they are the reference implementations
that the plugin guide points contributors at.
"""

from argus.scanners import ast_python, dependencies, iac, patterns, secrets  # noqa: F401

__all__ = ["ast_python", "dependencies", "iac", "patterns", "secrets"]
