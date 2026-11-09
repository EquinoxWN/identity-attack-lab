"""Attack-path graph: BFS shortest paths, deterministic ties, reverse exposure, entry points."""

from __future__ import annotations

import pytest

from identity_attack_lab.paths import (
    Edge,
    Graph,
    Node,
    analyze,
    entry_points,
    normalize_path,
    short_name,
)


def _graph() -> Graph:
    """a -> b -> DA (2 hops), a -> c -> d -> DA (3 hops), e isolated, k kerberoastable."""
    g = Graph()
    for oid, kind, name, t0 in [
        ("a", "User", "A@D.TEST", False),
        ("b", "Group", "B@D.TEST", False),
        ("c", "User", "C@D.TEST", False),
        ("d", "Computer", "D.D.TEST", False),
        ("da", "Group", "DOMAIN ADMINS@D.TEST", True),
        ("e", "User", "E@D.TEST", False),
    ]:
        g.add_node(Node(oid, kind, name, tier_zero=t0))
    g.add_node(Node("k", "User", "K@D.TEST", has_spn=True))
    g.add_node(Node("r", "User", "R@D.TEST", dont_req_preauth=True))
    g.add_edge("a", "MemberOf", "b")
    g.add_edge("b", "GenericAll", "da")
    g.add_edge("a", "AdminTo", "c")
    g.add_edge("c", "AdminTo", "d")
    g.add_edge("d", "HasSession", "da")
    g.add_edge("k", "MemberOf", "b")
    return g


def test_shortest_path_prefers_fewest_hops() -> None:
    g = _graph()
    path = g.shortest_path("a")
    assert path == [Edge("a", "MemberOf", "b"), Edge("b", "GenericAll", "da")]
    assert g.format_path("a", path) == "A -MemberOf-> B -GenericAll-> DOMAIN ADMINS"


def test_no_path_returns_none() -> None:
    assert _graph().shortest_path("e") is None


def test_tier_zero_start_is_zero_hops() -> None:
    assert _graph().shortest_path("da") == []


def test_unknown_start_raises() -> None:
    with pytest.raises(KeyError):
        _graph().shortest_path("zz")


def test_ties_break_by_edge_kind_then_name() -> None:
    g = Graph()
    g.add_node(Node("s", "User", "S"))
    g.add_node(Node("t", "Group", "T", tier_zero=True))
    for mid, kind in [("m2", "WriteDacl"), ("m1", "GenericAll"), ("m3", "GenericAll")]:
        g.add_node(Node(mid, "User", mid.upper()))
        g.add_edge("s", kind, mid)
        g.add_edge(mid, "MemberOf", "t")
    path = g.shortest_path("s")
    assert path is not None
    assert path[0] == Edge("s", "GenericAll", "m1")


def test_longer_path_is_found_when_short_one_is_missing() -> None:
    g = _graph()
    g.out["b"].clear()
    path = g.shortest_path("a")
    assert path is not None
    assert [e.dst for e in path] == ["c", "d", "da"]


def test_exposed_is_reverse_reachability() -> None:
    assert _graph().exposed() == {"a", "b", "c", "d", "k"}


def test_exposed_empty_without_tier_zero() -> None:
    g = Graph()
    g.add_edge("x", "MemberOf", "y")
    assert g.exposed() == set()


def test_edge_validation_and_placeholders() -> None:
    g = Graph()
    with pytest.raises(ValueError, match="not traversable"):
        g.add_edge("a", "ReadProperty", "b")
    g.add_edge("a", "MemberOf", "a")
    assert g.edges() == []
    g.add_edge("a", "MemberOf", "b")
    assert g.nodes["b"].kind == "Unknown"
    g.add_node(Node("b", "Group", "B"))
    assert g.nodes["b"].kind == "Group"


def test_conflicting_node_definitions_rejected() -> None:
    g = Graph()
    g.add_node(Node("a", "User", "A"))
    g.add_node(Node("a", "User", "A"))
    g.add_node(Node("a", "Unknown", "a"))
    assert g.nodes["a"].kind == "User"
    with pytest.raises(ValueError, match="defined twice"):
        g.add_node(Node("a", "Group", "A"))


def test_entry_points_and_reasons() -> None:
    g = _graph()
    entries = dict(entry_points(g, {"a", "E"}))
    assert entries == {
        "a": ("owned",),
        "e": ("owned",),
        "k": ("kerberoastable",),
        "r": ("asrep-roastable",),
    }


def test_owned_principal_must_exist() -> None:
    with pytest.raises(KeyError, match="not in the graph"):
        entry_points(_graph(), {"mallory"})


def test_analyze_reports_hops_and_none() -> None:
    by_start = {f.start: f for f in analyze(_graph(), {"a", "e"})}
    assert by_start["A"].hops == 2
    assert by_start["E"].path is None
    assert by_start["E"].hops is None
    assert by_start["K"].path == "K -MemberOf-> B -GenericAll-> DOMAIN ADMINS"
    assert by_start["R"].path is None


def test_find_and_short_names() -> None:
    g = _graph()
    assert g.find("domain admins") == "da"
    assert g.find("d") == "d"
    with pytest.raises(KeyError):
        g.find("nobody")
    assert short_name(Node("x", "Domain", "CORP.IDLAB.TEST")) == "corp.idlab.test"
    assert short_name(Node("x", "Computer", "ws01.corp.idlab.test")) == "WS01"
    assert short_name(Node("x", "Unknown", "S-1-5-21-1")) == "S-1-5-21-1"


def test_normalize_path() -> None:
    assert normalize_path("  Alice  -GenericAll->\tBOB ") == "alice -genericall-> bob"
