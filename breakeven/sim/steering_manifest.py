"""Typed construction and validation for content-steering manifests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class ManifestValidationError(ValueError):
    """Raised when a steering manifest cannot safely be published."""


@dataclass(frozen=True)
class SteeringManifest:
    """A version-1 content-steering manifest awaiting publication."""

    version: int
    ttl: int
    reload_uri: str
    pathway_priority: tuple[str, ...]
    pathway_clones: tuple[Mapping[str, object], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise ManifestValidationError(
                f"structural validity failed: VERSION must be an integer, got {self.version!r}"
            )
        if self.version != 1:
            raise ManifestValidationError(
                f"VERSION pinning failed: VERSION {self.version!r} is not supported"
            )
        if not isinstance(self.ttl, int) or isinstance(self.ttl, bool) or self.ttl <= 0:
            raise ManifestValidationError(
                f"structural validity failed: TTL must be a positive integer, got {self.ttl!r}"
            )
        if not isinstance(self.reload_uri, str) or not self.reload_uri.strip():
            raise ManifestValidationError(
                "structural validity failed: RELOAD-URI must be a non-empty string"
            )
        if not isinstance(self.pathway_priority, tuple) or not self.pathway_priority:
            raise ManifestValidationError(
                "structural validity failed: PATHWAY-PRIORITY must be a non-empty tuple"
            )
        if any(not isinstance(pathway, str) or not pathway.strip() for pathway in self.pathway_priority):
            raise ManifestValidationError(
                "structural validity failed: PATHWAY-PRIORITY entries must be non-empty strings"
            )
        if not isinstance(self.pathway_clones, tuple):
            raise ManifestValidationError(
                "structural validity failed: PATHWAY-CLONES must be a tuple"
            )
        for clone in self.pathway_clones:
            if not isinstance(clone, Mapping):
                raise ManifestValidationError(
                    "structural validity failed: PATHWAY-CLONES entries must be objects"
                )
            clone_id = clone.get("ID")
            if not isinstance(clone_id, str) or not clone_id.strip():
                raise ManifestValidationError(
                    "structural validity failed: PATHWAY-CLONES entries require a non-empty ID"
                )

    def to_json(self) -> dict[str, object]:
        """Return the JSON-shaped steering manifest ready for serialization."""
        return {
            "VERSION": self.version,
            "TTL": self.ttl,
            "RELOAD-URI": self.reload_uri,
            "PATHWAY-PRIORITY": list(self.pathway_priority),
            "PATHWAY-CLONES": [dict(clone) for clone in self.pathway_clones],
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> SteeringManifest:
        """Build a manifest from the required JSON-keyed representation."""
        required_keys = {
            "VERSION",
            "TTL",
            "RELOAD-URI",
            "PATHWAY-PRIORITY",
            "PATHWAY-CLONES",
        }
        if set(value) != required_keys:
            raise ManifestValidationError(
                "structural validity failed: manifest must contain exactly "
                f"{sorted(required_keys)!r}, got {sorted(value)!r}"
            )
        priority = value["PATHWAY-PRIORITY"]
        clones = value["PATHWAY-CLONES"]
        if not isinstance(priority, list) or not isinstance(clones, list):
            raise ManifestValidationError(
                "structural validity failed: PATHWAY-PRIORITY and PATHWAY-CLONES must be arrays"
            )
        return cls(
            version=value["VERSION"],
            ttl=value["TTL"],
            reload_uri=value["RELOAD-URI"],
            pathway_priority=tuple(priority),
            pathway_clones=tuple(clones),
        )


def validate_pathway_existence(
    manifest: SteeringManifest, live_pathway_ids: frozenset[str]
) -> None:
    """Reject manifests that reference pathways absent from the live inventory."""
    referenced_pathways = (*manifest.pathway_priority, *(clone["ID"] for clone in manifest.pathway_clones))
    unknown_pathways = tuple(
        pathway for pathway in referenced_pathways if pathway not in live_pathway_ids
    )
    if unknown_pathways:
        raise ManifestValidationError(
            "pathway-existence check failed: unknown pathway IDs "
            f"{', '.join(unknown_pathways)}"
        )
