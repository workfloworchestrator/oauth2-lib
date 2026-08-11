# OAuth2-lib

[![pypi_version](https://img.shields.io/pypi/v/oauth2-lib?color=%2334D058&label=pypi%20package)](https://pypi.org/project/oauth2-lib)
[![Supported python versions](https://img.shields.io/pypi/pyversions/oauth2-lib.svg?color=%2334D058)](https://pypi.org/project/oauth2-lib)
[![codecov](https://codecov.io/gh/workfloworchestrator/oauth2-lib/graph/badge.svg?token=JDMMBBOVM4)](https://codecov.io/gh/workfloworchestrator/oauth2-lib)

This project contains a number of classes to perform authentication (AuthN) and authorization (AuthZ) in a FastAPI application.

They can be found in [oauth2_lib/fastapi.py](oauth2_lib/fastapi.py).
Most notable are:
- `OIDCAuth`: AuthN implementation that authenticates a user against a OIDC backend. You can subclass and implement `def userinfo()` as needed.
  - To use a different AuthN method, subclass the `Authentication` base class.
- `OIDCUserModel`: model of the data returned by `OIDCAuth`. You can subclass this to rename and/or add fields.
- `OPAAuthorization`: AuthZ implementation that authorizes a user's HTTP request against an Open Policy Agent (OPA) instance.
  - To use a different AuthZ method, subclass the `Authorization` base class.
- `GraphQLOPAAuthorization`: AuthZ implementation that authorizes a user's GraphQL query against an Open Policy Agent (OPA) instance.
  - To use a different AuthZ method, subclass the `GraphqlAuthorization` base class.
- `OPAResult`: model of the data returned by `OPAAuthorization` and `GraphQLOPAAuthorization`.

The [orchestrator-core documentation](https://workfloworchestrator.org/orchestrator-core) has a section on Authentication and Authorization that describes how to use/override these classes.

## Upgrading to 3.0.0

3.0.0 replaces `httpx` with [`httpx2`](https://httpx2.pydantic.dev). The client passed to
`OIDCAuth.userinfo()`, `OIDCAuth.check_openid_config()` and `OPAMixin.get_decision()` is now an
`httpx2.AsyncClient`, so subclasses must import from `httpx2` instead of `httpx`:

```python
from httpx2 import AsyncClient  # was: from httpx import AsyncClient


class MyOIDCAuth(OIDCAuth):
    async def userinfo(
        self, async_request: AsyncClient, token: str
    ) -> OIDCUserModel: ...
```

Annotations alone will only fail type checking, but any *value* you pass back into that client must
also come from `httpx2` — an `httpx.BasicAuth`, `Timeout` or `Limits` raises `TypeError` at runtime.
The `httpx[http2]` extra is gone as well; the library only ever made HTTP/1.1 requests, so `h2` is no
longer installed transitively.

## Installation

To install the package from PyPI:

```bash
pip install oauth2-lib
```

## Development

### Virtual Environment

Steps to setup a virtual environment.

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and create the development environment:

```bash
uv sync --locked --group test --group dev
```

Run project commands through that environment with `uv run`, for example:

```bash
uv run pytest
```

### Unit tests

Run the unit tests through the uv-managed environment:

```bash
uv run pytest
```

### Pre-commit

This project uses [pre-commit](https://pre-commit.com/) to automatically run a number of checks before making a git commit.
The same checks will be performed in the CI pipeline so this can save you some time.

First ensure you have pre-commit installed.
It is recommended to install it outside the virtualenv.
On Linux and Mac, pre-commit is available in most package managers. Alternatively you can install it globally with [pipx](https://github.com/pypa/pipx).

Once pre-commit is installed, go into the project root and enable it:
```bash
pre-commit install
```

This should output `pre-commit installed at .git/hooks/pre-commit`. The next time you run `git commit` the pre-commit hooks will validate your changes.

### Set the package version

When a release version has been assigned, update the package metadata on a clean branch with `uv version`:

```bash
uv version 2.7.1
```

Specify the full version explicitly so release candidates can be represented, for example `uv version 2.7.1rc1`.

## Supported Python versions

oauth2-lib must support the same python versions as [orchestrator-core](https://github.com/workfloworchestrator/orchestrator-core).

Exceptions to this rule are:
* **A new python version is released:** oauth2-lib should support the new version before orchestrator-core does
* **Support for an old python version is dropped:** oauth2-lib should drop the python version after orchestrator-core does
