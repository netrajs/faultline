"""The synthetic identity/asset graph.

``GraphBuilder`` is the one place that mints node and edge identifiers, so
every caller -- background population, planted scenarios, planted decoys --
gets ids from the same deterministic counter rather than inventing its own
scheme. ``scenarios.py`` and ``decoys.py`` both take a builder that already
holds the background graph and add to it; nothing here writes a path, and
nothing here writes ``CAN_ESCALATE_TO`` or any other derived fact -- only the
ten primitive edge types this project allows.

Node kinds and edge types mirror ``core.model.NodeKind`` / ``EdgeType``, which
mirror ``node_kind`` / ``edge_type`` in the database. Attribute names mirror
what ``backend/db/seed/020_attacker_model.sql`` actually reads (via
``rule_precondition.attr_path``), not just the prose in ``docs/RULES.md`` --
the seed rows are the executable spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from faker import Faker

from core.ids import SeedBundle, edge_id, node_id
from core.model import Edge, EdgeType, Node, NodeKind

from . import attributes as attr


# ── Builder ──────────────────────────────────────────────────────────────────


class GraphBuilder:
    """Accumulates nodes and edges under one deterministic id scheme.

    Ids are assigned by insertion order within a kind, so reproducing the same
    sequence of calls from the same seed reproduces the same ids. Determinism
    therefore lives in the caller's control flow being fixed, not in anything
    clever here -- which is why generation always proceeds background, then
    scenarios, then decoys, in that fixed order.
    """

    def __init__(self, bundle: SeedBundle) -> None:
        self.bundle = bundle
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self._kind_counters: dict[str, int] = {}
        self._edge_discriminators: dict[tuple[str, str, str], int] = {}

    def add_node(
        self,
        kind: str,
        *,
        name: str,
        display_name: str | None = None,
        is_crown_jewel: bool = False,
        criticality: str | None = None,
        classification: str | None = None,
        attrs: dict | None = None,
    ) -> Node:
        index = self._kind_counters.get(kind, 0)
        self._kind_counters[kind] = index + 1
        nid = node_id(self.bundle, kind, index)
        node = Node(
            node_id=nid,
            kind=kind,
            name=name,
            display_name=display_name,
            is_crown_jewel=is_crown_jewel,
            criticality=criticality,
            classification=classification,
            attrs=dict(attrs or {}),
        )
        self.nodes[nid] = node
        return node

    def add_edge(
        self,
        edge_type: str,
        src: Node | str,
        dst: Node | str,
        attrs: dict | None = None,
    ) -> Edge:
        src_id = src.node_id if isinstance(src, Node) else src
        dst_id = dst.node_id if isinstance(dst, Node) else dst
        key = (edge_type, src_id, dst_id)
        discriminator = self._edge_discriminators.get(key, 0)
        self._edge_discriminators[key] = discriminator + 1
        eid = edge_id(self.bundle, edge_type, src_id, dst_id, discriminator)
        edge = Edge(edge_id=eid, src_id=src_id, dst_id=dst_id, edge_type=edge_type, attrs=dict(attrs or {}))
        self.edges[eid] = edge
        return edge

    def node_count(self, kind: str) -> int:
        return self._kind_counters.get(kind, 0)


# ── Background population ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class BackgroundSizes:
    """How much noise surrounds the planted opportunities.

    Deliberately modest -- a few hundred to low thousands of nodes, per
    ``docs/SCOPE.md``. The 2000-node target there is for graph-viz decisions,
    not a floor this generator needs to hit.
    """

    users: int = 140
    groups: int = 36
    service_accounts: int = 34
    hosts: int = 70
    databases: int = 18
    cloud_resources: int = 28
    applications: int = 22
    group_nesting_depth: int = 3


@dataclass(frozen=True, slots=True)
class Background:
    """Handles onto the population, for scenarios and decoys to build from."""

    users: list[Node]
    groups: list[Node]
    security_groups: list[Node]
    service_accounts: list[Node]
    hosts: list[Node]
    databases: list[Node]
    cloud_resources: list[Node]
    applications: list[Node]
    credentials_by_owner: dict[str, list[Node]] = field(default_factory=dict)


def _faker_for(bundle: SeedBundle, purpose: str) -> Faker:
    """A Faker instance seeded from the bundle, never from Faker's own global state."""
    fake = Faker()
    seed_int = bundle.stream(purpose).randint(0, 2**32 - 1)
    fake.seed_instance(seed_int)
    return fake


def build_background(builder: GraphBuilder, sizes: BackgroundSizes = BackgroundSizes()) -> Background:
    """Populate the graph with the noise a real directory and estate would have.

    This is what gives the rule preconditions in ``docs/RULES.md`` real values
    to evaluate against instead of gaps -- every attribute a rule reads is set
    here with a realistic, non-degenerate distribution (``attributes.py``).
    """
    bundle = builder.bundle
    fake = _faker_for(bundle, "background.faker")
    rng = bundle.stream("background.attrs")
    topo_rng = bundle.stream("background.topology")

    users = _build_users(builder, sizes, fake, rng)
    groups, security_groups = _build_groups(builder, sizes, fake, rng, topo_rng, users)
    service_accounts = _build_service_accounts(builder, sizes, fake, rng)
    hosts = _build_hosts(builder, sizes, fake, rng)
    databases = _build_databases(builder, sizes, fake, rng)
    cloud_resources = _build_cloud_resources(builder, sizes, fake, rng)
    applications = _build_applications(builder, sizes, fake, rng)

    credentials_by_owner = _build_credentials(
        builder, rng, users=users, service_accounts=service_accounts
    )

    _build_vulnerabilities(builder, rng, hosts=hosts, applications=applications)
    _build_permissions(builder, rng, topo_rng, security_groups, hosts, databases, cloud_resources, applications)
    _build_direct_admin(builder, rng, topo_rng, users, service_accounts, hosts, databases, cloud_resources)
    _build_service_account_access(builder, rng, topo_rng, service_accounts, databases, applications, cloud_resources)
    _build_authenticates_to(builder, rng, topo_rng, credentials_by_owner, hosts, applications, databases, cloud_resources)
    _build_trusts(builder, rng, topo_rng, hosts)
    _build_connections(builder, rng, topo_rng, cloud_resources)
    _build_exposed_credentials(builder, rng, topo_rng, hosts, applications, credentials_by_owner)

    return Background(
        users=users,
        groups=groups,
        security_groups=security_groups,
        service_accounts=service_accounts,
        hosts=hosts,
        databases=databases,
        cloud_resources=cloud_resources,
        applications=applications,
        credentials_by_owner=credentials_by_owner,
    )


def _build_users(builder, sizes, fake, rng) -> list[Node]:
    out = []
    for _ in range(sizes.users):
        name = fake.user_name()
        out.append(
            builder.add_node(
                NodeKind.USER.value,
                name=name,
                display_name=fake.name(),
                attrs={
                    "department": fake.job(),
                    "account_status": attr.account_status(rng),
                    "mfa_enabled": True,
                    "email": f"{name}@example.corp",
                },
            )
        )
    return out


def _build_groups(builder, sizes, fake, rng, topo_rng, users) -> tuple[list[Node], list[Node]]:
    groups: list[Node] = []
    for i in range(sizes.groups):
        gtype = attr.group_type(rng)
        groups.append(
            builder.add_node(
                NodeKind.GROUP.value,
                name=f"{fake.word()}-{fake.word()}-grp-{i:03d}",
                attrs={"type": gtype},
            )
        )

    security_groups = [g for g in groups if g.attrs["type"] == "security"]

    # Nest groups into a shallow tree so R1's fixpoint has real depth to climb.
    # Every group but the roots gets exactly one parent, chosen from an earlier
    # group, so the nesting graph is acyclic by construction.
    roots = max(1, len(groups) // (sizes.group_nesting_depth + 2))
    for i, group in enumerate(groups):
        if i < roots:
            continue
        parent = groups[topo_rng.randrange(0, i)]
        if parent.node_id == group.node_id:
            continue
        builder.add_edge(EdgeType.MEMBER_OF.value, group, parent, attrs={})

    # Users join a handful of groups directly, favouring security groups.
    for user in users:
        n_memberships = topo_rng.choice([1, 1, 2, 2, 3])
        pool = security_groups if security_groups else groups
        for group in topo_rng.sample(pool, k=min(n_memberships, len(pool))):
            builder.add_edge(EdgeType.MEMBER_OF.value, user, group, attrs={})

    return groups, security_groups


def _build_service_accounts(builder, sizes, fake, rng) -> list[Node]:
    out = []
    for i in range(sizes.service_accounts):
        out.append(
            builder.add_node(
                NodeKind.SERVICE_ACCOUNT.value,
                name=f"svc-{fake.word()}-{i:03d}",
                display_name=f"Service account {i:03d}",
                attrs={
                    "account_status": attr.account_status(rng),
                    "has_spn": attr.chance(rng, 0.28),
                    "credential_strength": attr.credential_strength(rng),
                    "is_interactive": attr.chance(rng, 0.35),
                },
            )
        )
    return out


def _crown_jewel_roll(rng, index: int, every: int, p: float) -> bool:
    return index % every == 0 and attr.chance(rng, p)


def _build_hosts(builder, sizes, fake, rng) -> list[Node]:
    out = []
    for i in range(sizes.hosts):
        crown = _crown_jewel_roll(rng, i, 12, 0.5)
        out.append(
            builder.add_node(
                NodeKind.HOST.value,
                name=f"host-{fake.hostname()}",
                is_crown_jewel=crown,
                criticality=attr.criticality(rng) if not crown else "critical",
                classification=attr.classification(rng),
                attrs={
                    "os": rng.choice(["windows_server", "linux", "windows_workstation"]),
                    "patch_level": attr.patch_level(rng),
                    "account_status": "active",
                    "status": attr.asset_status(rng),
                },
            )
        )
    return out


def _build_databases(builder, sizes, fake, rng) -> list[Node]:
    out = []
    for i in range(sizes.databases):
        crown = _crown_jewel_roll(rng, i, 6, 0.6)
        out.append(
            builder.add_node(
                NodeKind.DATABASE.value,
                name=f"db-{fake.word()}-{i:03d}",
                is_crown_jewel=crown,
                criticality=attr.criticality(rng) if not crown else "critical",
                classification=attr.classification(rng),
                attrs={
                    "engine": rng.choice(["postgres", "mysql", "mssql", "oracle"]),
                    "requires_separate_key": attr.chance(rng, 0.22),
                    "status": attr.asset_status(rng),
                },
            )
        )
    return out


def _build_cloud_resources(builder, sizes, fake, rng) -> list[Node]:
    out = []
    for i in range(sizes.cloud_resources):
        out.append(
            builder.add_node(
                NodeKind.CLOUD_RESOURCE.value,
                name=f"cloud-{fake.word()}-{i:03d}",
                criticality=attr.criticality(rng),
                classification=attr.classification(rng),
                attrs={
                    "resource_type": rng.choice(["bucket", "function", "workload", "queue"]),
                    "status": attr.asset_status(rng),
                },
            )
        )
    return out


def _build_applications(builder, sizes, fake, rng) -> list[Node]:
    out = []
    for i in range(sizes.applications):
        out.append(
            builder.add_node(
                NodeKind.APPLICATION.value,
                name=f"app-{fake.word()}-{i:03d}",
                criticality=attr.criticality(rng),
                classification=attr.classification(rng),
                attrs={"status": attr.asset_status(rng)},
            )
        )
    return out


def _build_credentials(builder, rng, *, users, service_accounts) -> dict[str, list[Node]]:
    by_owner: dict[str, list[Node]] = {}
    for owner in [*users, *service_accounts]:
        n = 2 if attr.chance(rng, 0.12) else 1
        creds = []
        for _ in range(n):
            strength = owner.attrs.get("credential_strength") or attr.credential_strength(rng)
            cred = builder.add_node(
                NodeKind.CREDENTIAL.value,
                name=f"cred-{owner.name}-{len(creds)}",
                attrs={
                    "credential_type": rng.choice(["password", "api_key", "cert", "token"]),
                    "storage": attr.credential_storage(rng),
                    "is_active": attr.chance(rng, 0.90),
                    "strength": strength,
                },
            )
            builder.add_edge(EdgeType.HAS_CREDENTIAL.value, owner, cred, attrs={})
            creds.append(cred)
        by_owner[owner.node_id] = creds
    return by_owner


def _build_vulnerabilities(builder, rng, *, hosts, applications) -> None:
    for host in hosts:
        if not attr.chance(rng, 0.35):
            continue
        impact = attr.vuln_impact(rng)
        vector = attr.vuln_attack_vector(rng)
        vuln = builder.add_node(
            NodeKind.VULNERABILITY.value,
            name=f"CVE-{rng.randint(2019, 2025)}-{rng.randint(1000, 99999)}",
            attrs={
                "impact": impact,
                "attack_vector": vector,
                "epss": attr.epss(rng),
                "cvss": attr.cvss(rng),
            },
        )
        builder.add_edge(EdgeType.HAS_VULNERABILITY.value, host, vuln, attrs={})

    for app in applications:
        if not attr.chance(rng, 0.30):
            continue
        impact = attr.vuln_impact(rng)
        vector = attr.vuln_attack_vector(rng)
        vuln = builder.add_node(
            NodeKind.VULNERABILITY.value,
            name=f"CVE-{rng.randint(2019, 2025)}-{rng.randint(1000, 99999)}",
            attrs={
                "impact": impact,
                "attack_vector": vector,
                "epss": attr.epss(rng),
                "cvss": attr.cvss(rng),
            },
        )
        builder.add_edge(EdgeType.HAS_VULNERABILITY.value, app, vuln, attrs={})


def _build_permissions(builder, rng, topo_rng, security_groups, hosts, databases, cloud_resources, applications) -> None:
    targets = [*hosts, *databases, *cloud_resources, *applications]
    if not security_groups or not targets:
        return
    for group in security_groups:
        n_targets = topo_rng.choice([0, 1, 1, 2])
        for target in topo_rng.sample(targets, k=min(n_targets, len(targets))):
            builder.add_edge(
                EdgeType.HAS_PERMISSION.value,
                group,
                target,
                attrs={"permission_level": attr.permission_level(rng)},
            )


def _build_direct_admin(builder, rng, topo_rng, users, service_accounts, hosts, databases, cloud_resources) -> None:
    targets = [*hosts, *databases, *cloud_resources]
    if not targets:
        return
    for principal in [*users, *service_accounts]:
        if not attr.chance(rng, 0.10):
            continue
        target = topo_rng.choice(targets)
        builder.add_edge(EdgeType.ADMIN_TO.value, principal, target, attrs={})


def _build_service_account_access(builder, rng, topo_rng, service_accounts, databases, applications, cloud_resources) -> None:
    targets = [*databases, *applications, *cloud_resources]
    if not targets:
        return
    for sa in service_accounts:
        n = topo_rng.choice([1, 1, 2])
        for target in topo_rng.sample(targets, k=min(n, len(targets))):
            builder.add_edge(
                EdgeType.HAS_ACCESS_TO.value,
                sa,
                target,
                attrs={"permission_level": attr.permission_level(rng)},
            )


def _build_authenticates_to(builder, rng, topo_rng, credentials_by_owner, hosts, applications, databases, cloud_resources) -> None:
    targets = [*hosts, *applications, *databases, *cloud_resources]
    if not targets:
        return
    for creds in credentials_by_owner.values():
        for cred in creds:
            if not attr.chance(rng, 0.7):
                continue
            target = topo_rng.choice(targets)
            factor = attr.mfa_type(rng)
            builder.add_edge(
                EdgeType.AUTHENTICATES_TO.value,
                cred,
                target,
                attrs={
                    "mfa_required": factor != "none",
                    "mfa_type": factor,
                    "requires_compliant_device": attr.chance(rng, 0.08),
                    "scope": "admin" if attr.chance(rng, 0.12) else "standard",
                },
            )


def _build_trusts(builder, rng, topo_rng, hosts) -> None:
    if len(hosts) < 2:
        return
    n_trusts = max(1, len(hosts) // 6)
    for _ in range(n_trusts):
        src, dst = topo_rng.sample(hosts, k=2)
        builder.add_edge(
            EdgeType.TRUSTS.value,
            src,
            dst,
            attrs={
                "bidirectional": attr.chance(rng, 0.35),
                "trust_type": attr.trust_type(rng),
            },
        )


def _build_connections(builder, rng, topo_rng, cloud_resources) -> None:
    if len(cloud_resources) < 2:
        return
    n_connections = max(1, len(cloud_resources) // 2)
    for _ in range(n_connections):
        src, dst = topo_rng.sample(cloud_resources, k=2)
        ctype = attr.connection_type(rng)
        builder.add_edge(
            EdgeType.CONNECTED_TO.value,
            src,
            dst,
            attrs={
                "connection_type": ctype,
                "grants_admin": attr.chance(rng, 0.15) if ctype == "iam_assume_role" else False,
            },
        )


def _build_exposed_credentials(builder, rng, topo_rng, hosts, applications, credentials_by_owner) -> None:
    all_creds = [c for creds in credentials_by_owner.values() for c in creds]
    if not all_creds:
        return
    carriers = [*hosts, *applications]
    for carrier in carriers:
        if not attr.chance(rng, 0.18):
            continue
        cred = topo_rng.choice(all_creds)
        builder.add_edge(
            EdgeType.EXPOSES_CREDENTIAL.value,
            carrier,
            cred,
            attrs={"location": attr.credential_location(rng)},
        )
