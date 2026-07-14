"""Report formats.

Each reporter turns a :class:`~argus.core.models.ScanResult` into a string in one
format. Importing this package registers the built-in reporters. Add a format by
subclassing :class:`~argus.core.plugin.Reporter` and decorating with ``@reporter``.
"""

from argus.reporting import (  # noqa: F401
    gitlab,
    html,
    json_reporter,
    markdown,
    sarif,
)

__all__ = ["gitlab", "html", "json_reporter", "markdown", "sarif"]
