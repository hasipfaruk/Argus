# Releasing Argus to PyPI

Argus publishes to PyPI automatically when you publish a GitHub Release. Publishing
uses **PyPI Trusted Publishing (OIDC)**, so no API token is ever stored in the
repository. You do a one-time setup, then every release is a few clicks.

The package is published as **`argus-appsec`** (the installed command is `argus`).

---

## One-time setup (do this once)

### 1. Create a PyPI account

- Go to <https://pypi.org/account/register/> and create an account.
- Enable two-factor authentication when prompted (PyPI requires it for publishing).

### 2. Add a "pending" trusted publisher

This tells PyPI to trust releases coming from your GitHub repo, before the
project even exists on PyPI.

- Go to <https://pypi.org/manage/account/publishing/>.
- Under **Add a new pending publisher**, fill in exactly:
  - **PyPI Project Name:** `argus-appsec`
  - **Owner:** `Argus-CodeSecurity`
  - **Repository name:** `Argus-appsec`
  - **Workflow name:** `publish.yml`
  - **Environment name:** `pypi`
- Click **Add**.

### 3. Create the GitHub environment

- In your repo: **Settings → Environments → New environment**.
- Name it exactly `pypi` and save. (No secrets needed, OIDC handles auth.)

That's it for setup.

---

## Cutting a release (each time)

1. **Bump the version** in `pyproject.toml` (e.g. `version = "0.5.2"`) and in
   `src/argus/__init__.py` (`__version__`). Keep them in sync. Commit and push.
2. On GitHub: **Releases → Draft a new release**.
3. **Choose a tag** like `v0.5.2` (create it on publish), targeting `main`.
4. Write a short changelog in the description, then **Publish release**.
5. The **Publish to PyPI** workflow runs automatically, builds the package, and
   uploads it. Watch it under the **Actions** tab.
6. When it's green, `pip install argus-appsec` installs your new version.

---

## Versioning

Argus follows [Semantic Versioning](https://semver.org):

- **PATCH** (`0.5.2`), bug fixes, no behavior change.
- **MINOR** (`0.2.0`), new features, backward compatible (new scanner, format).
- **MAJOR** (`1.0.0`), breaking changes to the CLI or plugin API.

During alpha (`0.x`) minor versions may still change behavior; call it out in the
release notes.

---

## Testing a release first (optional but recommended)

To rehearse without touching real PyPI, publish to **TestPyPI**:

1. Register the same pending publisher at <https://test.pypi.org/manage/account/publishing/>.
2. Temporarily add `repository-url: https://test.pypi.org/legacy/` to the publish
   step, cut a pre-release, confirm it works, then revert.
3. Install from TestPyPI to verify:
   `pip install -i https://test.pypi.org/simple/ argus-appsec`

---

## Manual publish (fallback)

If you ever need to publish from your machine instead of CI:

```bash
python -m build
python -m twine upload dist/*        # prompts for a PyPI API token
```

Create the token at <https://pypi.org/manage/account/token/>. Prefer the automated
trusted-publishing flow above for normal releases.
