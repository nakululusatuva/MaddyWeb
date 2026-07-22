# Contributing

MaddyWeb uses English as its sole engineering language. Every new or rewritten commit must follow these rules:

- Write commit subjects, bodies, and trailers in English.
- Use English for source code identifiers, comments, docstrings, user-interface text, tests, fixtures, configuration, scripts, and documentation.
- Use ASCII for all language-bearing text and tracked paths. This makes the mechanical policy deterministic; reviewers must still confirm that ASCII prose is meaningful English.
- Do not add a non-English localization catalog or embed non-English text in an encoded form to bypass the policy.
- Binary assets may use the narrowly allowlisted suffixes in `scripts/check-english-policy.py`, but their names and surrounding metadata must remain English ASCII.

After creating or amending a commit and before pushing, run:

```bash
python scripts/check-english-policy.py --repository . --ref HEAD
python -m pytest -q
python -m ruff check .
```

The history check scans every commit reachable from the selected ref, not only the final tree. Translating a later snapshot does not repair non-English content in an earlier commit; rewrite and verify the affected history before pushing.
