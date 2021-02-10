import sys

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand

test_requirements = [
    "apache-license-check",
    "black",
    "flake8",
    "flake8-bandit",
    "flake8-bugbear",
    "flake8-comprehensions",
    "flake8-docstrings",
    "flake8-junit-report",
    "flake8-logging-format",
    "flake8-pep3101",
    "flake8-print",
    "flake8-rst",
    "flake8-rst-docstrings",
    "flake8-tidy-imports",
    "isort",
    "mypy",
    "pygments",
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "pytest-xdist",
    "requests_mock",
    "pre-commit",
]


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass into py.test")]

    def initialize_options(self) -> None:
        TestCommand.initialize_options(self)
        self.pytest_args = []  # type:ignore

    def finalize_options(self) -> None:
        TestCommand.finalize_options(self)
        self.test_args = []  # type:ignore
        self.test_suite = True

    def run_tests(self) -> None:
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setup(
    name="oauth2-lib",
    version="1.0.22",
    packages=find_packages(),
    cmdclass={"test": PyTest},
    url="https://gitlab.surfnet.nl/automation/oauth2-lib",
    classifiers=["License :: OSI Approved :: MIT License", "Programming Language :: Python :: 3.x"],
    license="MIT",
    author="Automation",
    author_email="automation-nw@surfnet.nl",
    description="OAUTH2 lib specific for SURFnet",
    install_requires=[
        "requests>=2.19.0",
        "ruamel.yaml~=0.16.10",
        "structlog>=20.2.0",
        "fastapi>=0.61.2",
        "httpx~=0.16.1",
        "authlib>=0.15.2",
        "pydantic",
        "opentelemetry-api~=0.17b0",
        "opentelemetry-instrumentation~=0.17b0",
    ],
    extras_require={"test": test_requirements},
    tests_require=test_requirements,
)
