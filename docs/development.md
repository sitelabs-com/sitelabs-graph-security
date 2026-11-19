<!-- menu -->
[Overview](overview.md) · [Callers](keys.md) · [Protections](admin-login.md) · **Using it** · [References](index.md)

**Using it:** [In a FastAPI app](fastapi.md) · **Development**
<!-- /menu -->

# Development

> **For:** developers of this package. **You'll find:** the tests, changing it beside an application,
> releasing, and the documentation site.

## The tests

```bash
pip install -e ".[test]"
python -m pytest
```

The tests make their own keys, tokens and certificates: no identity provider and no network.

## Changing it beside an application

Install a checkout in place of the release an application pins, run the application's tests, then
release:

```bash
pip install --no-deps -e ../sitelabs-graph-security       # in the application's environment
```

The settings' names and defaults are shared: a new setting goes in `SecuritySettings`, in each
application's `Settings`, and on the [Settings](settings.md) page.

## Releasing

1. Change the version in `pyproject.toml` (`0.3.0`), and move the changelog's **Unreleased**
   entries under the new release ([CHANGELOG.md](../CHANGELOG.md)).
2. Commit, tag (`v0.3.0`) and push both. The tag publishes the release's documentation site.
3. In each application, pin the new tag (its `requirements.txt` and lock file), and change its links
   to this site to the new release (`/sitelabs-graph-security/0.3/`).

## The documentation site

`docs/` is published at https://sitelabs-com.github.io/sitelabs-graph-security/, one site per
release, with [mike](https://github.com/jimporter/mike):

* `/0.2/`, `/0.3/` ...: each release's site, for the code an application pins. Applications link
  to these.
* `/latest/`: the newest. The site's root sends browsers there.

`.github/workflows/mkdocs.yml` publishes the release in `pyproject.toml` on every push to `main` that
changes the docs, and on every tag. The menu at the top of each page and the sidebar come from
`GROUPS` in `tools/docs.py`:

```bash
python tools/docs.py                     # write the menus and mkdocs.yml's nav
python tools/docs.py --check             # change nothing; fail if a file is out of date
pip install -r requirements-docs.txt
mkdocs serve                             # the site at http://127.0.0.1:8000, as you edit
mkdocs build --strict                    # what the workflow builds, failing on a broken link
```
