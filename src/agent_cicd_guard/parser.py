"""Parse GitHub Actions workflow YAML, preserving line numbers and `on:` keys."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agent_cicd_guard.detect import annotate_agent_steps
from agent_cicd_guard.models import Job, Step, Workflow


class GHALoader(yaml.SafeLoader):
    """SafeLoader that does not coerce YAML 1.1 booleans such as `on` / `yes`."""


# GitHub Actions uses `on:` as a mapping key. PyYAML's default implicit
# resolver would turn that key into True.
for _ch, _resolvers in list(GHALoader.yaml_implicit_resolvers.items()):
    GHALoader.yaml_implicit_resolvers[_ch] = [
        (tag, regexp)
        for tag, regexp in _resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]


class LineStr(str):
    __slots__ = ("line", "column")

    def __new__(cls, value: str, line: int = 1, column: int = 0) -> "LineStr":
        obj = str.__new__(cls, value)
        obj.line = line
        obj.column = column
        return obj


class LineList(list):
    __slots__ = ("line", "column")

    def __init__(self, iterable=(), line: int = 1, column: int = 0):
        super().__init__(iterable)
        self.line = line
        self.column = column


class LineDict(dict):
    __slots__ = ("line", "column")

    def __init__(self, *args, line: int = 1, column: int = 0, **kwargs):
        super().__init__(*args, **kwargs)
        self.line = line
        self.column = column


def source_line(obj: Any, default: int | None = None) -> int | None:
    return getattr(obj, "line", default)


def _mark_line(node: yaml.Node) -> int:
    return node.start_mark.line + 1


def _mark_column(node: yaml.Node) -> int:
    return node.start_mark.column + 1


def _construct_mapping(loader: GHALoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict(line=_mark_line(node), column=_mark_column(node))
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        value = loader.construct_object(value_node, deep=True)
        mapping[key] = value
    return mapping


def _construct_sequence(loader: GHALoader, node: yaml.SequenceNode) -> LineList:
    seq = LineList(line=_mark_line(node), column=_mark_column(node))
    for child in node.value:
        seq.append(loader.construct_object(child, deep=True))
    return seq


def _construct_scalar(loader: GHALoader, node: yaml.ScalarNode) -> Any:
    # Keep values as strings with line info. GitHub expressions and
    # permission verbs are all strings in practice.
    tag = node.tag
    if tag in ("tag:yaml.org,2002:null",) and not node.value:
        return None
    if tag == "tag:yaml.org,2002:null" or node.value in ("null", "~") and tag.endswith("null"):
        return None
    if node.style is None and node.value.lower() in {"null", "~"} and tag.endswith("null"):
        return None
    # Explicit null from empty values
    if tag == "tag:yaml.org,2002:null":
        return None
    return LineStr(node.value, line=_mark_line(node), column=_mark_column(node))


GHALoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)
GHALoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence
)
GHALoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SCALAR_TAG, _construct_scalar
)


def parse_yaml(text: str) -> Any:
    return yaml.load(text, Loader=GHALoader)


def as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def trigger_map(on_value: Any) -> dict[str, Any]:
    """Normalize the `on:` field into a name -> config mapping."""
    if on_value is None:
        return {}
    if isinstance(on_value, dict):
        return {str(key): val for key, val in on_value.items()}
    names: dict[str, Any] = {}
    for item in as_list(on_value):
        names[str(item)] = None
    return names


def _extract_on(doc: dict[str, Any]) -> tuple[Any, int | None]:
    for key in ("on", True, "true", "True"):
        if key in doc:
            return doc[key], source_line(doc.get(key), source_line(key, source_line(doc)))
    return None, source_line(doc)


def _needs(value: Any) -> list[str]:
    return [str(item) for item in as_list(value)]


def _parse_step(index: int, raw: Any) -> Step:
    if not isinstance(raw, dict):
        return Step(index=index, line=source_line(raw), id=None, name=None, uses=None, run=as_str(raw))
    uses = as_str(raw.get("uses"))
    run = raw.get("run")
    run_text = as_str(run) if run is not None else None
    return Step(
        index=index,
        line=source_line(raw),
        id=as_str(raw.get("id")),
        name=as_str(raw.get("name")),
        uses=uses,
        run=run_text,
        with_args=as_mapping(raw.get("with")),
        env=as_mapping(raw.get("env")),
    )


def _parse_job(job_id: str, raw: Any) -> Job:
    data = as_mapping(raw)
    environment = data.get("environment")
    permissions = data.get("permissions")
    steps_raw = data.get("steps") or []
    steps = [_parse_step(i, item) for i, item in enumerate(as_list(steps_raw))]
    return Job(
        id=str(job_id),
        line=source_line(raw),
        name=as_str(data.get("name")),
        permissions=permissions,
        permissions_line=source_line(permissions),
        environment=environment,
        environment_line=source_line(environment) if environment is not None else None,
        needs=_needs(data.get("needs")),
        if_condition=as_str(data.get("if")),
        env=as_mapping(data.get("env")),
        steps=steps,
        raw=data,
    )


def parse_workflow_document(path: str, doc: Any) -> Workflow:
    if not isinstance(doc, dict):
        return Workflow(
            path=path,
            name=None,
            triggers={},
            trigger_line=None,
            permissions=None,
            permissions_line=None,
            parse_error="Workflow root is not a mapping",
        )
    on_value, on_line = _extract_on(doc)
    jobs_raw = as_mapping(doc.get("jobs"))
    jobs = [_parse_job(job_id, raw) for job_id, raw in jobs_raw.items()]
    workflow = Workflow(
        path=path,
        name=as_str(doc.get("name")),
        triggers=trigger_map(on_value),
        trigger_line=on_line or source_line(doc),
        permissions=doc.get("permissions"),
        permissions_line=source_line(doc.get("permissions")) if "permissions" in doc else None,
        jobs=jobs,
        env=as_mapping(doc.get("env")),
        raw=doc,
    )
    annotate_agent_steps(workflow)
    return workflow


def parse_workflow_text(path: str, text: str) -> Workflow:
    try:
        doc = parse_yaml(text)
    except yaml.YAMLError as exc:
        return Workflow(
            path=path,
            name=None,
            triggers={},
            trigger_line=None,
            permissions=None,
            permissions_line=None,
            parse_error=f"YAML parse error: {exc}",
        )
    return parse_workflow_document(path, doc)


def parse_workflow_file(path: Path) -> Workflow:
    text = path.read_text(encoding="utf-8")
    return parse_workflow_text(str(path), text)


WORKFLOW_SUFFIXES = {".yml", ".yaml"}


def discover_workflow_files(path: Path) -> list[Path]:
    """Find workflow files under a path (file, workflows dir, or repo root)."""
    path = path.resolve()
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []

    candidates = [
        path / ".github" / "workflows",
        path if path.name == "workflows" and path.parent.name == ".github" else None,
        path,
    ]
    found: list[Path] = []
    seen: set[Path] = set()
    for directory in candidates:
        if directory is None or not directory.is_dir():
            continue
        # For a generic directory that is not a workflows folder, only
        # recurse into .github/workflows when we already tried that, and
        # otherwise collect top-level YAML (used by tests/fixtures).
        if directory == path / ".github" / "workflows" or (
            directory.name == "workflows" and directory.parent.name == ".github"
        ):
            files = sorted(
                p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in WORKFLOW_SUFFIXES
            )
        elif directory == path and (path / ".github" / "workflows").is_dir():
            continue
        else:
            files = sorted(
                p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in WORKFLOW_SUFFIXES
            )
        for file in files:
            resolved = file.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(file)
    return found
