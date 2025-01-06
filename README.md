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

## Installation

To install the package from PyPI:

```bash
pip install oauth2-lib
```

## Development

### Virtual Environment

Steps to setup a virtual environment.

#### Step 1:

Create and activate a python3 virtualenv.

#### Step 2:

Install flit to enable you to develop on this repository:

```bash
pip install flit
```

#### Step 3:

To install all development dependencies:

```bash
flit install --deps develop
```

All steps combined into 1 command:

```bash
python -m venv .venv && source .venv/bin/activate && pip install -U pip && pip install flit && flit install --deps develop
```

### Unit tests

Activate the virtualenv and run the unit tests with:

```bash
pytest
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

### Bump version

Depending on the feature type, run bumpversion (patch|minor|major) to increment the version you are working on. For
example to update the increment the patch version use
```bash
bumpversion patch
```

## Supported Python versions

oauth2-lib must support the same python versions as [orchestrator-core](https://github.com/workfloworchestrator/orchestrator-core).

Exceptions to this rule are:
* **A new python version is released:** oauth2-lib should support the new version before orchestrator-core does
* **Support for an old python version is dropped:** oauth2-lib should drop the python version after orchestrator-core does
