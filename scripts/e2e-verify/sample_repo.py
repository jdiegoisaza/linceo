"""Builds the synthetic test repository the verification run scans.

Generated, not a real repository pointed at by a path — deliberately, and
the reason is stated once here rather than at every call site: a real
repository changes under this script's feet (a CVE gets patched upstream, a
synthetic secret gets "cleaned up" by someone who does not realize it is a
fixture, history grows), which is exactly what would make two runs of this
script produce different findings for the same code — useless for the
documentation-capture purpose this script exists for. The three files under
``fixtures/sample-repo/`` are the same kind of small, disposable, synthetic
tree the project's own golden fixtures already are
(``tests/unit/fixtures/{gitleaks,trivy,checkov}/``), each one already
validated against a real tool binary before being written here — not
invented values.

``--repo <path>`` (see ``run.py``) overrides this with a real path for
ad-hoc exploration; that path is never reproducible run to run, so its
output is explicitly never treated as a captured "case" (see ``run.py``'s
own gating on this).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample-repo"


def _git(*args: str, cwd: Path) -> None:
    argv = ["git", *args]  # `git` resolved via PATH on purpose
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)  # noqa: S603


def build_sample_repo(dest: Path) -> str:
    """Materialize the generated sample repository at ``dest`` and return its commit hash.

    ``dest`` must not already exist. Copies the checked-in template files
    verbatim, then ``git init``s and commits them — the one thing that
    cannot be made reproducible (a fresh commit hash every run, per the
    nature of `git commit`), which is exactly why `commit` is one of
    `normalize.py`'s own placeholder rules rather than something this
    function tries to pin.
    """
    dest.mkdir(parents=True)
    for source in _FIXTURES_DIR.iterdir():
        shutil.copy2(source, dest / source.name)

    _git("init", "-q", cwd=dest)
    _git("config", "user.email", "e2e-verify@example.com", cwd=dest)
    _git("config", "user.name", "linceo e2e-verify", cwd=dest)
    _git("add", "-A", cwd=dest)
    _git("commit", "-q", "-m", "e2e-verify sample repository", cwd=dest)

    argv = ["git", "rev-parse", "HEAD"]  # `git` resolved via PATH on purpose
    result = subprocess.run(argv, cwd=dest, check=True, capture_output=True, text=True)  # noqa: S603
    return result.stdout.strip()
