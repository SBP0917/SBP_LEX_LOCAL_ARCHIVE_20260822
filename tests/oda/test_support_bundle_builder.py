import json

from sbp_oda.profile.deployment_profile import build_default_deployment_profile
from sbp_oda.support.support_bundle_builder import build_support_bundle_manifest, write_support_bundle_manifest


def test_support_bundle_is_diagnostic_evidence_only(tmp_path) -> None:
    profile = build_default_deployment_profile(".")
    manifest = build_support_bundle_manifest(profile)

    assert manifest.bundle_type == "ODA_SUPPORT_BUNDLE"
    assert any("does not grant runtime authority" in note for note in manifest.notes)

    path = write_support_bundle_manifest(profile, tmp_path / "support_bundle.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["bundle_type"] == "ODA_SUPPORT_BUNDLE"
