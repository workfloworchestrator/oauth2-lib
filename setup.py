import sys

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand


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
    version="1.0.2",
    packages=find_packages(),
    cmdclass={"test": PyTest},
    url="https://gitlab.surfnet.nl/automation/oauth2-lib",
    classifiers=["License :: OSI Approved :: MIT License", "Programming Language :: Python :: 3.x"],
    license="MIT",
    author="Automation",
    author_email="automation-nw@surfnet.nl",
    description="OAUTH2 lib specific for SURFnet",
    install_requires=["flask<=1.0.3", "requests>=2.19.0", "ruamel.yaml==0.15.97"],
    tests_require=[
        "pytest",
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
        "mypy",
        "mypy_extensions",
        "requests_mock",
        "flask_testing",
        "pre-commit",
    ],
)
