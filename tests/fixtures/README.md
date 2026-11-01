# Conformance fixtures

Copied from the shared ZevAuth server SDK contract:
<https://github.com/zevop/zevauth-sdk/tree/main/spec/fixtures>.

Do not edit these by hand. Every ZevAuth server library (Node, PHP,
Python, Ruby, Go, Java) passes the same files, which is what keeps their
behaviour identical. Update them with:

```
python scripts/sync_fixtures.py ../zevauth-sdk/spec/fixtures
```

The keys behind these tokens are test-only and valid nowhere else. The
private keys are not copied here; only the public key sets are.
