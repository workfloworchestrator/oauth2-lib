# OAuth2-lib

[![pypi_version](https://img.shields.io/pypi/v/oauth2-lib?color=%2334D058&label=pypi%20package)](https://pypi.org/project/oauth2-lib)
[![Supported python versions](https://img.shields.io/pypi/pyversions/oauth2-lib.svg?color=%2334D058)](https://pypi.org/project/oauth2-lib)
[![codecov](https://codecov.io/gh/workfloworchestrator/oauth2-lib/graph/badge.svg?token=JDMMBBOVM4)](https://codecov.io/gh/workfloworchestrator/oauth2-lib)

This Project contains a Mixin class that wraps an openapi-codegen python client, to inject Opentelemetry spans
and api call retries. It also contains a number of FastAPI dependencies which enables Policy enforcement offloading
to Open Policy Agent.

The project contains a number of OIDC classes that are tailored to the SURF environment.


## Installation
This can be done as follows:

#### Step 1:
First install flit to enable you to develop on this repository
```bash
pip install flit
```
#### Step 2:

To install all development dependencies
```bash
flit install --deps develop --symlink
```

for pydantic V2 you also need to install pydantic_settings: `pip install pydantic_settings`.

This way all requirements are installed for testing and development.

## Development
Depending on the feature type, run bumpversion (patch|minor|major) to increment the version you are working on. For
example to update the increment the patch version use
```bash
bumpversion patch
```

## For MAC users looking and experimenting with Opentelemetry (OTEL)
https://github.com/jaegertracing/jaeger-client-node/issues/124#issuecomment-324222456

## Supported Python versions

oauth2-lib must support the same python versions as [orchestrator-core](https://github.com/workfloworchestrator/orchestrator-core).

Exceptions to this rule are:
* **A new python version is released:** oauth2-lib should support the new version before orchestrator-core does
* **Support for an old python version is dropped:** oauth2-lib should drop the python version after orchestrator-core does
