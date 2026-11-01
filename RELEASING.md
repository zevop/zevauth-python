# Releasing

Releases run in GitHub Actions and publish to PyPI with Trusted
Publishing: PyPI trusts the release workflow's identity, so there is no
PyPI token to store, rotate or leak.

## Cutting a release

1. Set the new version in `src/zevauth/_version.py` and commit it to
   `main`. Let the **CI** workflow pass.
2. Tag and push the tag:

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

   Or on GitHub: **Releases → Draft a new release → Choose a tag**, type
   `v0.2.0`, target `main`, and publish.

The **Release** workflow checks the tag matches `zevauth.__version__`,
runs the tests, builds the wheel and source archive, publishes them to
PyPI, and attaches them to a GitHub Release with generated notes. If you
added a required reviewer to the `pypi` environment, approve the run
under Actions first.

PyPI never accepts the same version twice. If a release fails after
publishing, bump the version and tag again.

## One-time setup

### 1. The `pypi` environment

GitHub → this repository → **Settings → Environments → New environment**,
named `pypi`. Optionally add yourself as a required reviewer, so every
release waits for your approval before it reaches PyPI.

### 2. The trusted publisher on PyPI

On pypi.org, open the `zevauth` project → **Manage → Publishing → Add a
new publisher → GitHub**, and enter:

| Field | Value |
| --- | --- |
| Owner | `zevop` |
| Repository name | `zevauth-python` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Once the first release from the workflow has succeeded, you can delete
the API token used for the first manual upload (Account settings → API
tokens).
