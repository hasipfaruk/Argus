"""Report formats.

Each reporter turns a :class:`~argus.core.models.ScanResult` into a string in one
format. Importing this package registers the built-in reporters. Add a format by
subclassing :class:`~argus.core.plugin.Reporter` and decorating with ``@reporter``.
"""

from argus.reporting import html, json_reporter, markdown, sarif  # noqa: F401

__all__ = ["html", "json_reporter", "markdown", "sarif"]
