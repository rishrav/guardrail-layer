from pathlib import Path

import pytest

from benchmarks.harness import CaseResult
from benchmarks.report import write_report

RESULTS_KEY = pytest.StashKey[list[CaseResult]]()
OUT_DIR = Path(__file__).parent / "out"


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("guardrail benchmark")
    group.addoption("--config", default="core", help="core | all | comma-separated config names")
    group.addoption("--split", default="test", choices=["dev", "test", "all"])
    group.addoption("--limit", type=int, default=0, help="run only the first N cases (smoke)")
    group.addoption(
        "--record",
        action="store_true",
        help="on cassette misses, call the live local models and record the responses",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.stash[RESULTS_KEY] = []


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    results = session.config.stash.get(RESULTS_KEY, [])
    if results:
        split = session.config.getoption("--split")
        write_report(results, split, OUT_DIR)
        print(f"\nbenchmark report written to {OUT_DIR / 'report.md'}")
