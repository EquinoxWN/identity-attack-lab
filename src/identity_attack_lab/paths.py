"""Attack-path graph: the question BloodHound answers, computed offline and deterministically.

Nodes are AD principals, computers and the domain; every edge points in the direction an attacker
gains control (`alice -GenericAll-> svc_backup` means whoever controls alice can take over
svc_backup). Tier Zero is the set of nodes whose control means control of the domain.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

# Edge kinds that transfer control, as BloodHound CE names them.
TRAVERSABLE = frozenset(
    {
        "MemberOf",
        "AdminTo",
        "HasSession",
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
        "AllExtendedRights",
        "DCSync",
    }
)


@dataclass(frozen=True)
class Node:
    """One object in the graph."""

    oid: str
    kind: str
    name: str
    tier_zero: bool = False
    has_spn: bool = False
    dont_req_preauth: bool = False


@dataclass(frozen=True, order=True)
class Edge:
    """A directed control edge `src -kind-> dst`."""

    src: str
    kind: str
    dst: str


@dataclass
class Graph:
    """Nodes by object id plus outgoing traversable edges."""

    nodes: dict[str, Node] = field(default_factory=dict)
    out: dict[str, set[Edge]] = field(default_factory=dict)

    def add_node(self, node: Node) -> None:
        """Insert or merge a node (a real node replaces an earlier placeholder)."""
        old = self.nodes.get(node.oid)
        if old is None or old.kind == "Unknown":
            self.nodes[node.oid] = node
        elif node.kind != "Unknown" and old != node:
            raise ValueError(f"object {node.oid} defined twice with different data")

    def add_edge(self, src: str, kind: str, dst: str) -> None:
        """Insert a traversable edge; unknown endpoints become placeholders."""
        if kind not in TRAVERSABLE:
            raise ValueError(f"edge kind {kind!r} is not traversable")
        if src == dst:
            return
        for oid in (src, dst):
            if oid not in self.nodes:
                self.nodes[oid] = Node(oid=oid, kind="Unknown", name=oid)
        self.out.setdefault(src, set()).add(Edge(src, kind, dst))

    def edges(self) -> list[Edge]:
        """All edges, sorted."""
        return sorted(e for es in self.out.values() for e in es)

    def tier_zero(self) -> set[str]:
        """Object ids of Tier Zero nodes."""
        return {oid for oid, n in self.nodes.items() if n.tier_zero}

    def _sorted_out(self, oid: str) -> list[Edge]:
        """Outgoing edges in a stable order (kind, then target name)."""
        return sorted(self.out.get(oid, ()), key=lambda e: (e.kind, self.nodes[e.dst].name, e.dst))

    def shortest_path(self, start: str) -> list[Edge] | None:
        """Breadth-first shortest path from `start` to any Tier Zero node, or None."""
        if start not in self.nodes:
            raise KeyError(f"unknown start object {start!r}")
        targets = self.tier_zero()
        if start in targets:
            return []
        parent: dict[str, Edge] = {}
        seen = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for edge in self._sorted_out(current):
                if edge.dst in seen:
                    continue
                seen.add(edge.dst)
                parent[edge.dst] = edge
                if edge.dst in targets:
                    path = [edge]
                    while path[0].src != start:
                        path.insert(0, parent[path[0].src])
                    return path
                queue.append(edge.dst)
        return None

    def exposed(self) -> set[str]:
        """Non-Tier-Zero nodes with at least one path into Tier Zero (reverse search)."""
        incoming: dict[str, list[str]] = {}
        for edge in self.edges():
            incoming.setdefault(edge.dst, []).append(edge.src)
        targets = self.tier_zero()
        seen = set(targets)
        queue = deque(targets)
        while queue:
            for src in incoming.get(queue.popleft(), ()):
                if src not in seen:
                    seen.add(src)
                    queue.append(src)
        return seen - targets

    def format_path(self, start: str, path: list[Edge]) -> str:
        """Render a path as `a -Kind-> b -Kind-> c` using short names."""
        parts = [short_name(self.nodes[start])]
        parts.extend(f"-{e.kind}-> {short_name(self.nodes[e.dst])}" for e in path)
        return " ".join(parts)

    def find(self, name: str) -> str:
        """Object id of the node whose short name matches `name` (case-insensitive)."""
        key = name.casefold()
        hits = sorted(oid for oid, n in self.nodes.items() if short_name(n).casefold() == key)
        if len(hits) != 1:
            raise KeyError(f"{len(hits)} objects are named {name!r}")
        return hits[0]


def short_name(node: Node) -> str:
    """`ALICE@CORP.IDLAB.TEST` -> `alice`-style names as written in the lab spec."""
    if node.kind == "Domain":
        return node.name.lower()
    if node.kind == "Computer":
        return node.name.split(".", 1)[0].upper()
    return node.name.rsplit("@", 1)[0] if "@" in node.name else node.name


def normalize_path(text: str) -> str:
    """Case- and whitespace-insensitive form of a path string, for comparisons."""
    return " ".join(text.split()).casefold()


@dataclass(frozen=True)
class Finding:
    """One entry point and its shortest path into Tier Zero (None when there is none)."""

    start: str
    reasons: tuple[str, ...]
    path: str | None
    hops: int | None


def entry_points(graph: Graph, owned: set[str]) -> list[tuple[str, tuple[str, ...]]]:
    """Owned principals plus users anyone in the domain can attack offline (roastable)."""
    owned_keys = {o.casefold() for o in owned}
    out = []
    for oid, node in sorted(graph.nodes.items(), key=lambda kv: short_name(kv[1]).casefold()):
        reasons = []
        if short_name(node).casefold() in owned_keys:
            reasons.append("owned")
        if node.kind == "User" and node.has_spn:
            reasons.append("kerberoastable")
        if node.kind == "User" and node.dont_req_preauth:
            reasons.append("asrep-roastable")
        if reasons:
            out.append((oid, tuple(reasons)))
    found = {short_name(graph.nodes[oid]).casefold() for oid, _ in out}
    missing = owned_keys - found
    if missing:
        raise KeyError(f"owned principal(s) not in the graph: {sorted(missing)}")
    return out


def analyze(graph: Graph, owned: set[str]) -> list[Finding]:
    """Shortest path into Tier Zero for every entry point."""
    findings = []
    for oid, reasons in entry_points(graph, owned):
        path = graph.shortest_path(oid)
        findings.append(
            Finding(
                start=short_name(graph.nodes[oid]),
                reasons=reasons,
                path=None if path is None else graph.format_path(oid, path),
                hops=None if path is None else len(path),
            )
        )
    return findings
