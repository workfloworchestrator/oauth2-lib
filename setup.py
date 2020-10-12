import sys

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand

test_requirements = [
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "flake8",
    "black",
    "isort",
    "flake8-bandit",
    "flake8-bugbear",
    "flake8-comprehensions",
    "flake8-docstrings",
    "flake8-logging-format",
    "flake8-pep3101",
    "flake8-print",
    "pydocstyle==3.0.0",
    "mypy",
    "mypy_extensions",
    "requests_mock",
    "flask_testing",
    "pre-commit",
]


class PyTest(TestCommand):
    user_options = [("pytest-args=", "a", "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setup(
    name="oauth2-lib",
    version="1.0.15",
    packages=find_packages(),
    cmdclass={"test": PyTest},
    url="https://gitlab.surfnet.nl/automation/oauth2-lib",
    classifiers=["License :: OSI Approved :: MIT License", "Programming Language :: Python :: 3.x"],
    license="MIT",
    author="Automation",
    author_email="automation-nw@surfnet.nl",
    description="OAUTH2 lib specific for SURFnet",
    install_requires=[
        "flask>=1.0.4",
        "requests>=2.19.0",
        "ruamel.yaml~=0.16.10",
        "structlog~=20.1.0",
        "fastapi>=0.54.1",
        "httpx~=0.12.0",
        "authlib==0.14",
        "pydantic",
        "opentracing==2.3.0",
    ],
    extras_require={"test": test_requirements},
    tests_require=test_requirements,
)
