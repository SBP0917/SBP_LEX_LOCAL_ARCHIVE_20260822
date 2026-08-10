from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class SceneNode:
    node_id: str
    parent_id: str | None
    payload: dict[str, Any]


class SceneGraph:
    """Deterministic object hierarchy with relationship and cycle checks."""

    def __init__(self, objects: Iterable[dict[str, Any]]) -> None:
        ordered = [deepcopy(item) for item in objects]
        self._order = [str(item.get("id", "")) for item in ordered]
        self._nodes: dict[str, SceneNode] = {}
        for item in ordered:
            node_id = str(item.get("id", ""))
            # Preserve the first declaration so a later duplicate cannot hide
            # relationship errors in the original graph.
            self._nodes.setdefault(
                node_id,
                SceneNode(
                    node_id=node_id,
                    parent_id=item.get("parent"),
                    payload=item,
                ),
            )

    @property
    def node_ids(self) -> tuple[str, ...]:
        return tuple(self._order)

    def node(self, node_id: str) -> SceneNode:
        return self._nodes[node_id]

    def children(self, node_id: str | None) -> tuple[SceneNode, ...]:
        return tuple(
            self._nodes[item_id]
            for item_id in self._order
            if self._nodes[item_id].parent_id == node_id
        )

    def validation_errors(self) -> list[str]:
        errors: list[str] = []
        if len(self._nodes) != len(self._order):
            errors.append("scene.objects:duplicate_id")
        for node_id in self._order:
            node = self._nodes[node_id]
            if node.parent_id == node_id:
                errors.append(f"scene.objects[{node_id}].parent:self_reference")
            elif node.parent_id is not None and node.parent_id not in self._nodes:
                errors.append(f"scene.objects[{node_id}].parent:unknown_object")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                errors.append(f"scene.objects[{node_id}].parent:cycle")
                return
            if node_id in visited:
                return
            visiting.add(node_id)
            parent_id = self._nodes[node_id].parent_id
            if parent_id in self._nodes:
                visit(parent_id)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in self._order:
            visit(node_id)
        return list(dict.fromkeys(errors))

    def topological_order(self) -> tuple[SceneNode, ...]:
        errors = self.validation_errors()
        if errors:
            raise ValueError("invalid scene graph: " + "; ".join(errors))
        indegree = {node_id: 0 for node_id in self._order}
        children: dict[str, list[str]] = defaultdict(list)
        for node_id in self._order:
            parent_id = self._nodes[node_id].parent_id
            if parent_id is not None:
                indegree[node_id] += 1
                children[parent_id].append(node_id)
        ready = [node_id for node_id in self._order if indegree[node_id] == 0]
        result: list[SceneNode] = []
        while ready:
            node_id = ready.pop(0)
            result.append(self._nodes[node_id])
            for child_id in children[node_id]:
                indegree[child_id] -= 1
                if indegree[child_id] == 0:
                    ready.append(child_id)
        return tuple(result)

    def world_transform(self, node_id: str) -> dict[str, list[float]]:
        """Compose the hierarchy's basic translation/rotation/scale channels."""

        chain: list[SceneNode] = []
        cursor: str | None = node_id
        while cursor is not None:
            node = self._nodes[cursor]
            chain.append(node)
            cursor = node.parent_id
        location = [0.0, 0.0, 0.0]
        rotation = [0.0, 0.0, 0.0]
        scale = [1.0, 1.0, 1.0]
        for node in reversed(chain):
            transform = node.payload.get("transform", {})
            for index, value in enumerate(transform.get("location", [0, 0, 0])):
                location[index] += float(value)
            for index, value in enumerate(transform.get("rotation", [0, 0, 0])):
                rotation[index] += float(value)
            for index, value in enumerate(transform.get("scale", [1, 1, 1])):
                scale[index] *= float(value)
        return {"location": location, "rotation": rotation, "scale": scale}
