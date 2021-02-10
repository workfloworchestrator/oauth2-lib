# OAuth2-lib
This project contains the SURFnet implementation of an OAuth2 filter.
The `oauth2_lib` module contains a number of classes that either filter an incoming OAuth2 response
or define Roles, Teams and Scopes.

## Rules
Rules can be defined by using a set of conditions. The conditions are AnyOf or AllOf. Meaning that rules defined within
these context will be enforced that way.

An example of how this is implemented can be found:

* [Workflows main.py](https://gitlab.surfnet.nl/automation/workflows/blob/dev/server/main.py#L223)

An example of a complex set of conditions may be found here:

* [Networkdashboard-api](https://gitlab.surfnet.nl/automation/netwerkdashboard-api/blob/dev/server/api/security_definitions.yaml)

## Installation
This can be done as follows:

```bash
python setup.py install test
```

With this way all requirements are installed for testing and development.

## Development
Don't forget to update the version number in setup.py before each update to master branch


## For MAC users looking and experimenting with Opentelemetry (OTEL)
https://github.com/jaegertracing/jaeger-client-node/issues/124#issuecomment-324222456
