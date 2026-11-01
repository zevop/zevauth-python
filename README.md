# ZevAuth for Python

Verify ZevAuth sessions, call the ZevAuth backend API and check webhook
signatures from FastAPI, Django, Flask or plain Python.

```bash
pip install zevauth                # core
pip install "zevauth[fastapi]"     # or [django], [flask]
```

Python 3.9 or newer.

## Verify a request

```python
from zevauth import ZevAuth

zevauth = ZevAuth(
    "env_live_…",                                   # your environment id
    secret_key=os.environ["ZEVAUTH_SECRET_KEY"],    # only for the backend API
)
```

Create it once, when your app starts: it caches your environment's keys,
so verifying a request does not touch the network.

### FastAPI

```python
from fastapi import Depends, FastAPI
from zevauth import Auth
from zevauth.fastapi import ZevAuthFastAPI

za = ZevAuthFastAPI(zevauth)
app = FastAPI()
za.install(app)

@app.get("/api/me")
async def me(auth: Auth = Depends(za.require_auth())):
    return {"userId": auth.user_id}
```

### Django

```python
# settings.py
ZEVAUTH = {"ENVIRONMENT_ID": "env_live_…", "SECRET_KEY": os.environ["ZEVAUTH_SECRET_KEY"]}
MIDDLEWARE = [..., "zevauth.django.ZevAuthMiddleware"]

# views.py
from zevauth.django import require_auth

@require_auth
def me(request):
    return JsonResponse({"userId": request.zevauth.user_id})
```

### Flask

```python
from flask import Flask, g
from zevauth.flask import ZevAuthFlask, require_auth

app = Flask(__name__)
ZevAuthFlask(app, zevauth)

@app.get("/api/me")
@require_auth
def me():
    return {"userId": g.zevauth.user_id}
```

`require_auth` refuses with the same JSON every ZevAuth library uses:
401 `unauthorized`, 403 `session_task_pending` (the user still has to set
up two-step verification), or 403 `mfa_required` when you pass
`require_mfa=True`.

## The backend API

```python
user = zevauth.api.users.create(email="ada@example.com", first_name="Ada")
for user in zevauth.api.users.iterate(metadata={"plan": "pro"}):
    ...
zevauth.api.users.reset_mfa(user["id"], revoke_sessions=True)
```

`zevauth.api_async` is the same API for asyncio. Failed calls raise
`ZevAuthError` with `code`, `status` and `request_id`. Rate limits and
gateway errors are retried for you; a 500 never is, because the request
may already have run.

## Webhooks

```python
from zevauth import construct_webhook_event

event = construct_webhook_event(
    request_body_bytes,                       # the raw body, exactly as received
    headers["zevauth-signature"],
    os.environ["ZEVAUTH_WEBHOOK_SECRET"],
)
```

## Server-rendered pages

Pages requested by the browser carry no `Authorization` header. Turn on
the session bridge and the browser SDK keeps an HttpOnly cookie on your
domain up to date:

```python
zevauth = ZevAuth("env_live_…", publishable_key="pk_live_…", session_bridge=True)
```

Each framework integration mounts the bridge for you. Details:
<https://docs.zevauth.com/concepts/session-bridge>.

## Documentation

<https://docs.zevauth.com/sdk/python>

Every ZevAuth server library implements the same contract and passes the
same conformance fixtures (vendored in `tests/fixtures`):
<https://github.com/zevop/zevauth-sdk/tree/main/spec>.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e ".[fastapi,django,flask]" pytest mypy ruff
.venv/bin/pytest
.venv/bin/mypy
.venv/bin/ruff check src tests
```

## Support

Questions and bug reports: open an issue here, or contact ZevAuth support.

## License

[MIT](LICENSE). Copyright (c) 2026 ZevOp Inc.
