#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


def run(cmd: List[str], cwd: Optional[Path] = None) -> None:
    subprocess.check_call(cmd, cwd=str(cwd) if cwd else None)


def ensure_repo(repo_url: str, local_dir: Path, ref: str = "master") -> None:
    if not local_dir.exists():
        local_dir.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", repo_url, str(local_dir)])
    # fetch + checkout ref (branch/tag/commit)
    run(["git", "fetch", "--all", "--tags"], cwd=local_dir)
    run(["git", "checkout", ref], cwd=local_dir)
    run(["git", "pull", "--ff-only"], cwd=local_dir)


def safe_id(s: str) -> str:
    out = []
    for ch in s.strip():
        out.append(ch if ch.isalnum() or ch in {"_"} else "_")
    s2 = "".join(out)
    if not s2:
        return "unnamed"
    if s2[0].isdigit():
        s2 = "_" + s2
    return s2


def load_openapi(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def deref_schema_ref(ref: Any) -> Optional[str]:
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        return ref.split("/")[-1]
    return None


def iter_operations(spec: Dict[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    ops: List[Tuple[str, str, Dict[str, Any]]] = []
    paths = spec.get("paths", {}) or {}
    if not isinstance(paths, dict):
        return ops
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            if isinstance(op, dict):
                ops.append((path, method.lower(), op))
    return ops


def op_tags(op: Dict[str, Any]) -> List[str]:
    tags = op.get("tags", []) or []
    return [t for t in tags if isinstance(t, str) and t.strip()]


def schema_refs_in_node(node: Any, out: Set[str]) -> None:
    if isinstance(node, dict):
        if "$ref" in node:
            name = deref_schema_ref(node["$ref"])
            if name:
                out.add(name)
        for v in node.values():
            schema_refs_in_node(v, out)
    elif isinstance(node, list):
        for v in node:
            schema_refs_in_node(v, out)


def schema_refs_in_op(op: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    schema_refs_in_node(op.get("requestBody"), out)
    schema_refs_in_node(op.get("responses"), out)
    schema_refs_in_node(op.get("parameters"), out)
    return out


def diagram_tag_overview(tag: str, ops: List[Tuple[str, str, Dict[str, Any]]]) -> str:
    lines: List[str] = []
    lines.append("flowchart TB")
    lines.append(f'  %% Tag overview: {tag}')
    tag_id = safe_id(tag)
    lines.append(f'  subgraph {tag_id}["{tag}"]')

    by_path: Dict[str, List[Tuple[str, Dict[str, Any]]]] = defaultdict(list)
    for path, method, op in ops:
        if tag in op_tags(op):
            by_path[path].append((method, op))

    if not by_path:
        lines.append('    empty["No operations found"]')
        lines.append("  end")
        return "\n".join(lines) + "\n"

    for path in sorted(by_path.keys()):
        node_path = safe_id(path)
        lines.append(f'    {node_path}["{path}"]')
        for method, op in sorted(by_path[path], key=lambda x: x[0]):
            opid = op.get("operationId") or method.upper()
            node_op = safe_id(f"{path}_{method}_{opid}")
            label = f'{method.upper()}\\n{opid}'
            lines.append(f'    {node_op}["{label}"]')
            lines.append(f"    {node_path} --> {node_op}")

    lines.append("  end")
    return "\n".join(lines) + "\n"


def extract_schema_edges(spec: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Set[str]]]:
    schemas: Dict[str, Dict[str, Any]] = (spec.get("components", {}) or {}).get("schemas", {}) or {}
    edges: Dict[str, Set[str]] = defaultdict(set)

    def harvest_refs(src: str, node: Any) -> None:
        if isinstance(node, dict):
            if "$ref" in node:
                tgt = deref_schema_ref(node["$ref"])
                if tgt and tgt != src:
                    edges[src].add(tgt)
            for v in node.values():
                harvest_refs(src, v)
        elif isinstance(node, list):
            for v in node:
                harvest_refs(src, v)

    for name, schema in schemas.items():
        harvest_refs(name, schema)

    return schemas, edges


def bfs_group(starts: Set[str], edges: Dict[str, Set[str]], limit: int) -> Set[str]:
    seen: Set[str] = set()
    q = deque(sorted(starts))
    while q and len(seen) < limit:
        n = q.popleft()
        if n in seen:
            continue
        seen.add(n)
        for nxt in sorted(edges.get(n, set())):
            if nxt not in seen:
                q.append(nxt)
    return seen


def diagram_class_schemas(group: Set[str], edges: Dict[str, Set[str]], title: str) -> str:
    lines: List[str] = []
    lines.append("classDiagram")
    lines.append(f"  %% {title}")
    for name in sorted(group):
        lines.append(f"  class {safe_id(name)}")
    for src in sorted(group):
        for tgt in sorted(edges.get(src, set())):
            if tgt in group:
                lines.append(f"  {safe_id(src)} --> {safe_id(tgt)}")
    return "\n".join(lines) + "\n"


def write(out_dir: Path, filename: str, text: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / filename).write_text(text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Clone/pull OpenBankingUK specs and generate Mermaid .mmd files from OpenAPI YAMLs.")
    ap.add_argument("--repo", default="https://github.com/OpenBankingUK/read-write-api-specs.git")
    ap.add_argument("--ref", default="master", help="Branch/tag/commit to use (e.g. master, main, v3.1.10)")
    ap.add_argument("--local", default="external/openbanking-read-write-api-specs", help="Local checkout directory")
    ap.add_argument("--spec-dir", default="dist/openapi", help="Folder (within repo) containing OpenAPI YAML files")
    ap.add_argument("--out", default="diagrams_from_openapi", help="Output directory for generated .mmd files")
    ap.add_argument("--schema-limit", type=int, default=60, help="Max schemas per schema diagram (keeps diagrams reviewable)")
    args = ap.parse_args()

    repo_dir = Path(args.local)
    ensure_repo(args.repo, repo_dir, ref=args.ref)

    spec_root = repo_dir / args.spec_dir
    if not spec_root.exists():
        raise SystemExit(f"Spec directory not found: {spec_root}")

    out_root = Path(args.out)
    yaml_files = sorted(list(spec_root.glob("*.yaml")) + list(spec_root.glob("*.yml")))
    if not yaml_files:
        print(f"No YAML files found in {spec_root}")
        return 0

    for ypath in yaml_files:
        spec = load_openapi(ypath)
        ops = iter_operations(spec)

        # output per spec in its own folder (nice for review)
        spec_name = ypath.stem
        out_dir = out_root / spec_name

        # tag overview diagrams
        tags: Set[str] = set()
        for _, _, op in ops:
            tags.update(op_tags(op))
        if not tags:
            tags = {"untagged"}

        for tag in sorted(tags):
            txt = diagram_tag_overview(tag, ops)
            write(out_dir, f"tag_{safe_id(tag)}_overview.mmd", txt)

        # schema relationship diagrams (seeded by tag usage)
        schemas, edges = extract_schema_edges(spec)

        tag_to_seeds: Dict[str, Set[str]] = defaultdict(set)
        for _, _, op in ops:
            for tag in (op_tags(op) or ["untagged"]):
                tag_to_seeds[tag].update(schema_refs_in_op(op))

        for tag, seeds in sorted(tag_to_seeds.items(), key=lambda x: x[0]):
            if not seeds:
                continue
            group = bfs_group(seeds, edges, limit=args.schema_limit)
            txt = diagram_class_schemas(group, edges, title=f"Schemas related to tag: {tag}")
            write(out_dir, f"schemas_{safe_id(tag)}.mmd", txt)

        print(f"Generated Mermaid diagrams for: {ypath.name} -> {out_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
