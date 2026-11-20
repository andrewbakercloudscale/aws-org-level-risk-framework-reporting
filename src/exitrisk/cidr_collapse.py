"""Observed addresses collapsed into the fewest CIDRs that grant the fewest never-seen addresses.

Ported from sg-tightener 2.2.0 (MIT, same author): each address widened as far as ``tolerance`` allows (never
past its RFC 1918 block, public addresses never widened), then, over the rule budget, the exact least-waste cover.
"""

from __future__ import annotations

import bisect
import ipaddress
from collections.abc import Callable, Iterable, Sequence

RFC1918_BLOCKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
DEFAULT_TOLERANCE = 0.30
DEFAULT_MAX_RULES = 60
DEFAULT_PREFIX_THRESHOLD = 24
_INF = float("inf")


def _normalise_ips(ips: Iterable[str]) -> list[ipaddress.IPv4Address]:
    out: list[ipaddress.IPv4Address] = []
    seen: set[ipaddress.IPv4Address] = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except (ValueError, AttributeError):
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _home_of(base: int, plen: int) -> int:
    """Index of the RFC 1918 block holding (base, plen), or -1 for any other address."""
    for i, b in enumerate(RFC1918_BLOCKS):
        if plen >= b.prefixlen and (base >> (32 - b.prefixlen)) == (int(b.network_address) >> (32 - b.prefixlen)):
            return i
    return -1


def _count_in(xs: list[int], base: int, size: int) -> int:
    """How many of the sorted addresses ``xs`` fall in [base, base + size)."""
    return bisect.bisect_left(xs, base + size) - bisect.bisect_left(xs, base)


def _widest_block_for(
    addr: ipaddress.IPv4Address,
    observed: set[ipaddress.IPv4Address] | None,
    tolerance: float,
    xs: list[int] | None = None,
) -> ipaddress.IPv4Network:
    """Widest containing CIDR where (block_size - observed_in_block)/block_size <= tolerance.

    Always returns at least the /32 host route, and never widens past the
    RFC 1918 block the address belongs to. ``xs`` (the observed addresses as
    sorted integers) makes each count a binary search instead of a scan.
    """
    home_block = next((b for b in RFC1918_BLOCKS if addr in b), None)
    if home_block is None:
        return ipaddress.ip_network(f"{addr}/32")
    if xs is None:
        xs = sorted(int(o) for o in observed or ())
    a = int(addr)
    best = 32
    for prefix in range(31, home_block.prefixlen - 1, -1):
        size = 1 << (32 - prefix)
        in_block = _count_in(xs, a & ~(size - 1), size)
        if (size - in_block) / size <= tolerance:
            best = prefix
        else:
            break
    return ipaddress.ip_network((a & ~((1 << (32 - best)) - 1), best))


def _tolerance_blocks(
    xs: list[int],
    tolerance: float,
    within: ipaddress.IPv4Network | None = None,
) -> list[tuple[int, int, int]]:
    """Layer 1: every address widened as far as ``tolerance`` allows, merged.

    Returns disjoint (base, prefix length, observed count) blocks in address
    order. With ``within``, a block that grew past it is clipped back to it.
    These blocks are the finest cover sg-tightener will ever grant: their
    headroom is what ``--tolerance`` buys.
    """
    nets = set()
    for a in xs:
        n = _widest_block_for(ipaddress.IPv4Address(a), None, tolerance, xs)
        if within is not None and not n.subnet_of(within):
            n = within
        nets.add(n)
    out = []
    for n in ipaddress.collapse_addresses(nets):
        base = int(n.network_address)
        out.append((base, n.prefixlen, _count_in(xs, base, n.num_addresses)))
    return out


class _Node:
    __slots__ = ("base", "cost", "left", "plen", "right", "waste")


class _Cover:
    """The least wasteful way to cover a set of blocks with at most k CIDRs.

    ``leaves`` are disjoint (base, prefix length, observed count) blocks that
    must all be covered, and only whole: a leaf is never split. A covering
    CIDR is only ever the smallest one around some of the leaves, so the
    candidates are the nodes of the compressed binary tree over them, and for
    each node the cheapest cover with k CIDRs follows from its two children
    (cost = addresses granted that were never observed). ``curve[k]`` is that
    cost for the whole set; ``blocks(k)`` returns the CIDRs, fewest first on a
    tie. Exact, and O(leaves x kmax) rather than exponential.
    """

    def __init__(self, leaves: list[tuple[int, int, int]], kmax: int):
        self.kmax = max(1, kmax)
        self.root = self._build(leaves, 0, len(leaves))
        self.curve = self.root.cost

    def _build(self, leaves, lo: int, hi: int) -> _Node:
        node = _Node()
        node.left = node.right = None
        if hi - lo == 1:
            node.base, node.plen, count = leaves[lo]
            node.waste = (1 << (32 - node.plen)) - count
            node.cost = [_INF, node.waste]
            return node
        first = leaves[lo][0]
        last_base, last_plen, _ = leaves[hi - 1]
        last = last_base + (1 << (32 - last_plen)) - 1
        node.plen = 32 - (first ^ last).bit_length()
        node.base = first & ~((1 << (32 - node.plen)) - 1)
        mid = node.base + (1 << (31 - node.plen))
        split = bisect.bisect_left(leaves, (mid,), lo, hi)
        node.left = self._build(leaves, lo, split)
        node.right = self._build(leaves, split, hi)
        size = 1 << (32 - node.plen)
        node.waste = size - sum(c for _b, _p, c in leaves[lo:hi])
        left, right = node.left.cost, node.right.cost
        cap = min(self.kmax, len(left) - 1 + len(right) - 1)
        cost = [_INF] * (cap + 1)
        for i in range(1, len(left)):
            li = left[i]
            for j in range(1, min(len(right), cap - i + 1)):
                v = li + right[j]
                if v < cost[i + j]:  # noqa: PLR1730 (hot loop; min() is slower)
                    cost[i + j] = v
        cost[1] = node.waste
        for k in range(2, cap + 1):
            cost[k] = min(cost[k], node.waste, cost[k - 1])
        node.cost = cost
        return node

    def cost(self, k: int) -> float:
        return self.curve[min(k, len(self.curve) - 1)] if k >= 1 else _INF

    def blocks(self, k: int) -> list[ipaddress.IPv4Network]:
        out: list[ipaddress.IPv4Network] = []
        self._pick(self.root, k, out)
        return sorted(out, key=lambda n: (int(n.network_address), n.prefixlen))

    def _pick(self, node: _Node, k: int, out: list) -> None:
        cost = node.cost
        k = min(max(k, 1), len(cost) - 1)
        while k > 1 and cost[k] == cost[k - 1]:
            k -= 1
        if cost[k] == node.waste or node.left is None:
            out.append(ipaddress.ip_network((node.base, node.plen)))
            return
        left, right = node.left.cost, node.right.cost
        for i in range(max(1, k - len(right) + 1), min(len(left) - 1, k - 1) + 1):
            if left[i] + right[k - i] == cost[k]:
                self._pick(node.left, i, out)
                self._pick(node.right, k - i, out)
                return
        raise AssertionError("cover reconstruction failed")  # pragma: no cover


def _split_budget(curves: list[Callable[[int], float]], sizes: list[int], budget: int) -> list[int]:
    """Slots per cover that minimise the total waste, at least one each.

    ``curves[i](k)`` is cover i's waste with k CIDRs, flat beyond ``sizes[i]``.
    Exact (a knapsack over the covers), and the fewest slots on a tie. When
    the covers outnumber the budget, each gets one and the result is over it.
    """
    n = len(curves)
    if n == 0:
        return []
    if budget <= n:
        return [1] * n
    # best[b]: least waste of the covers so far using exactly b slots.
    best = [0.0] + [_INF] * budget
    choice: list[list[int]] = []
    for i, curve in enumerate(curves):
        nxt = [_INF] * (budget + 1)
        pick = [0] * (budget + 1)
        top = min(sizes[i], budget - (n - 1 - i))
        for b in range(i, budget + 1):
            if best[b] == _INF:
                continue
            for k in range(1, min(top, budget - b) + 1):
                v = best[b] + curve(k)
                if v < nxt[b + k]:
                    nxt[b + k], pick[b + k] = v, k
        best = nxt
        choice.append(pick)
    b = min(range(budget + 1), key=lambda x: (best[x], x))
    out = [0] * n
    for i in range(n - 1, -1, -1):
        out[i] = choice[i][b]
        b -= out[i]
    return out


def collapse_ips_to_cidrs(
    ips: Sequence[str],
    max_rules: int = DEFAULT_MAX_RULES,
    tolerance: float = DEFAULT_TOLERANCE,
) -> list[str]:
    """Collapse observed IPs into a CIDR list <= max_rules in size.

    Layer 1: widen each IP to the widest block respecting ``tolerance`` (never
    past its RFC 1918 block), and merge.
    Layer 2: if that is over budget, choose the at most ``max_rules`` CIDRs
    that cover those blocks granting the fewest never-observed addresses
    (see _Cover), sharing the budget across the RFC 1918 blocks the same way.
    Public addresses are never merged with anything.

    Returns sorted ``"a.b.c.d/p"`` strings.
    """
    xs = sorted({int(a) for a in _normalise_ips(ips)})
    if not xs:
        return []
    t = max(0.0, min(1.0, tolerance))
    leaves = _tolerance_blocks(xs, t)
    if len(leaves) <= max_rules:
        return [str(ipaddress.ip_network((b, p))) for b, p, _c in leaves]

    by_home: dict[int, list] = {}
    singles = []
    for leaf in leaves:
        home = _home_of(leaf[0], leaf[1])
        if home < 0:
            singles.append([leaf])
        else:
            by_home.setdefault(home, []).append(leaf)
    covers = [_Cover(g, max_rules) for g in list(by_home.values()) + singles]
    slots = _split_budget([c.cost for c in covers], [len(c.curve) - 1 for c in covers], max_rules)
    nets = [n for c, k in zip(covers, slots, strict=True) for n in c.blocks(k)]
    nets.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in nets]
