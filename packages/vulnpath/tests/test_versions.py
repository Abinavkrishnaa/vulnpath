from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from packaging.version import Version

from vulnpath.advisories import Match, match_version
from vulnpath_schema.osv import AffectedRange, RangeEvent, RangeType


def _range(*events: dict[str, Any], kind: RangeType = RangeType.ECOSYSTEM) -> AffectedRange:
    return AffectedRange(type=kind, events=tuple(RangeEvent(**e) for e in events))


SIMPLE = _range({"introduced": "0"}, {"fixed": "3.0.6"})


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.3.3", Match.AFFECTED),
        ("3.0.5", Match.AFFECTED),
        ("3.0.6", Match.NOT_AFFECTED),
        ("3.1.0", Match.NOT_AFFECTED),
        ("3.0.6rc1", Match.AFFECTED),  # pre-release sorts before the fix
    ],
)
def test_introduced_zero_fixed(version: str, expected: Match) -> None:
    assert match_version(version, [SIMPLE]) is expected


def test_multiple_windows_in_one_range() -> None:
    rng = _range({"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.5"})
    assert match_version("0.9", [rng]) is Match.NOT_AFFECTED
    assert match_version("1.2", [rng]) is Match.AFFECTED
    assert match_version("1.7", [rng]) is Match.NOT_AFFECTED
    assert match_version("2.4", [rng]) is Match.AFFECTED
    assert match_version("2.5", [rng]) is Match.NOT_AFFECTED


def test_unsorted_events_are_handled() -> None:
    rng = _range({"fixed": "2.5"}, {"introduced": "2.0"})
    assert match_version("2.1", [rng]) is Match.AFFECTED


def test_last_affected_is_inclusive() -> None:
    rng = _range({"introduced": "1.0"}, {"last_affected": "1.4"})
    assert match_version("1.4", [rng]) is Match.AFFECTED
    assert match_version("1.4.1", [rng]) is Match.NOT_AFFECTED


def test_limit_caps_the_range() -> None:
    rng = _range({"introduced": "0"}, {"limit": "2.0"})
    assert match_version("1.9", [rng]) is Match.AFFECTED
    assert match_version("2.0", [rng]) is Match.NOT_AFFECTED


def test_explicit_versions_list() -> None:
    assert match_version("1.0.0", [], versions=["1.0", "1.1"]) is Match.AFFECTED
    assert match_version("1.2", [], versions=["1.0", "1.1"]) is Match.NOT_AFFECTED


def test_invalid_versions_are_undetermined_never_not_affected() -> None:
    assert match_version("not-a-version", [SIMPLE]) is Match.UNDETERMINED
    broken = _range({"introduced": "0"}, {"fixed": "garbage!!"})
    assert match_version("1.0", [broken]) is Match.UNDETERMINED


def test_git_ranges_are_undetermined() -> None:
    git = _range({"introduced": "abc123"}, {"fixed": "def456"}, kind=RangeType.GIT)
    assert match_version("1.0", [git]) is Match.UNDETERMINED
    # An ecosystem range that matches still wins.
    assert match_version("1.0", [git, SIMPLE]) is Match.AFFECTED


def test_no_ranges_means_not_affected() -> None:
    assert match_version("1.0", []) is Match.NOT_AFFECTED


_versions = st.tuples(st.integers(0, 20), st.integers(0, 20), st.integers(0, 20)).map(
    lambda t: Version(".".join(map(str, t)))
)


@given(a=_versions, b=_versions, v=_versions)
def test_single_window_matches_half_open_interval(a: Version, b: Version, v: Version) -> None:
    if not a < b:
        return
    rng = _range({"introduced": str(a)}, {"fixed": str(b)})
    expected = Match.AFFECTED if a <= v < b else Match.NOT_AFFECTED
    assert match_version(str(v), [rng]) is expected
