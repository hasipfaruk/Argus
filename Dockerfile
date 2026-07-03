# Argus container image.
#
# Multi-stage build: install into a venv in the builder, copy the venv into a
# slim runtime. Includes git so remote repository targets can be cloned.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install .

# --- runtime ---------------------------------------------------------------
FROM python:3.12-slim AS runtime

# git is needed to scan remote repositories.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Run as a non-root user.
RUN useradd --create-home --uid 10001 argus
USER argus
WORKDIR /work

# Mount the project to scan at /work.
ENTRYPOINT ["argus"]
CMD ["--help"]
