# Contributing

Install the locked development dependencies before making changes:

```bash
python -m pip install -r requirements-dev.lock
```

Keep changes focused, add tests for behavior changes, and run the local
verification suite before opening a pull request:

```bash
python -m pytest -q
python -m ruff check .
```

Security-sensitive changes should include regression coverage for both the Web
process and the privileged helper boundary.
