"""Console entry point for linceo.

Translates command-line arguments into domain objects; contains no
orchestration logic of its own — see ``AGENTS.md``, "CLI framework", for
the rule this module must satisfy.
"""

import typer

from linceo import __version__
from linceo.cli.scan import scan_app

# Exit code for CLI usage errors, per
# docs/adr/ADR-000-arquitectura-base-y-alcance-v0.1.md, §8: "usage error or
# configuration error" maps to exit code 2. Fixed as a module constant
# rather than left to whatever Typer's underlying dependency happens to
# default to, because §8 declares exit codes a public contract covered by
# semver.
EXIT_USAGE_ERROR = 2

app = typer.Typer(
    name="linceo",
    add_completion=False,
    help="Orchestrate DevSecOps tool executions into a single verdict.",
)
app.add_typer(scan_app, name="scan")


def _print_version_and_exit(*, show_version: bool) -> None:
    """Print the installed version and exit 0, if the flag was passed."""
    if show_version:
        typer.echo(__version__)
        raise typer.Exit(code=0)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(  # noqa: ARG001 — bound to --version by Typer; see callback
        False,
        "--version",
        help="Print the installed linceo version and exit.",
        is_eager=True,
        callback=lambda show_version: _print_version_and_exit(show_version=show_version),
    ),
) -> None:
    """Orchestrate DevSecOps tool executions into a single verdict."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help(), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR)


def main() -> None:
    """Console-script entry point registered in ``pyproject.toml``."""
    app()
