"""
Runs tests and other routines.

Usage:
  1. Install "nox"
  2. Run "nox" or "nox -s test"
"""

import nox

nox.needs_version = ">=2025.02.09"

PYPROJECT = nox.project.load_toml()
PYTHON_VERSIONS = nox.project.python_versions(PYPROJECT, max_version="3.12")


@nox.session(python=PYTHON_VERSIONS)
def test_parsers(session):
    """Test parsers"""
    session.install("-e", ".[testing,parsers]")
    session.run("mwcp", "test", "-y")


@nox.session(python=PYTHON_VERSIONS)
def test_framework(session):
    """Test framework code"""
    session.install("-e", ".[testing,server]")
    session.run("pytest", "-m", "framework")


@nox.session(python=PYTHON_VERSIONS, tags=["package"])
def build(session):
    """Build source and wheel distribution"""
    session.install("build")
    session.run("python", "-m", "build")


@nox.session(tags=["package"])
def lint(session):
    session.install("flake8")
    # stop the build if there are Python syntax errors or undefined names
    session.run("flake8", "src", "--count", "--select=E9,F63,F7,F82", "--show-source", "--statistics")
    # only warn on less serious things - exit-zero treats all errors as warnings.
    session.run(
        "flake8", "src",
        "--count", "--exit-zero",
        "--ignore=E203,W503,W291,W293",
        "--max-complexity=10",
        "--max-line-length=150",
        "--statistics"
    )


@nox.session(tags=["package"])
def twine(session):
    session.install("twine")
    session.run("twine", "check", "dist/*")


@nox.session(python=False, default=False)
def release_patch(session):
    """Generate release patch"""
    session.run("mkdir", "-p", "dist", external=True)
    with open("./dist/updates.patch", "w") as out:
        session.run(
            "git", "format-patch", "--stdout", "master",
            external=True,
            stdout=out
        )
