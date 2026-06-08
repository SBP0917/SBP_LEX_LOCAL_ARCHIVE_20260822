from __future__ import annotations

from typing import Any, Dict, Mapping

AP_ACF_CLASSES = {
    "CLASS_1": {
        "label": "Minimal Risk",
        "risk_level": 1,
        "default_autonomy_ceiling": 25,
        "requires_monitoring": False,
        "critical": False,
    },
    "CLASS_2": {
        "label": "Low Risk",
        "risk_level": 2,
        "default_autonomy_ceiling": 40,
        "requires_monitoring": False,
        "critical": False,
    },
    "CLASS_3": {
        "label": "Moderate Risk",
        "risk_level": 3,
        "default_autonomy_ceiling": 50,
        "requires_monitoring": True,
        "critical": False,
    },
    "CLASS_4": {
        "label": "High Risk Standard",
        "risk_level": 4,
        "default_autonomy_ceiling": 60,
        "requires_monitoring": True,
        "critical": False,
    },
    "CLASS_4B": {
        "label": "High Risk Bounded",
        "risk_level": 4,
        "default_autonomy_ceiling": 75,
        "requires_monitoring": True,
        "critical": False,
    },
    "CLASS_4A": {
        "label": "High Risk Autonomous",
        "risk_level": 4,
        "default_autonomy_ceiling": 90,
        "requires_monitoring": True,
        "critical": False,
    },
    "CLASS_5": {
        "label": "Critical Risk Standard",
        "risk_level": 5,
        "default_autonomy_ceiling": 50,
        "requires_monitoring": True,
        "critical": True,
    },
    "CLASS_5B": {
        "label": "Critical Risk Bounded",
        "risk_level": 5,
        "default_autonomy_ceiling": 75,
        "requires_monitoring": True,
        "critical": True,
    },
    "CLASS_5A": {
        "label": "Critical Risk Autonomous",
        "risk_level": 5,
        "default_autonomy_ceiling": 100,
        "requires_monitoring": True,
        "critical": True,
    },
}

CLASS_ALIASES = {
    "1": "CLASS_1",
    "class 1": "CLASS_1",
    "class_1": "CLASS_1",
    "2": "CLASS_2",
    "class 2": "CLASS_2",
    "class_2": "CLASS_2",
    "3": "CLASS_3",
    "class 3": "CLASS_3",
    "class_3": "CLASS_3",
    "4": "CLASS_4",
    "class 4": "CLASS_4",
    "class_4": "CLASS_4",
    "4b": "CLASS_4B",
    "class 4b": "CLASS_4B",
    "class_4b": "CLASS_4B",
    "4a": "CLASS_4A",
    "class 4a": "CLASS_4A",
    "class_4a": "CLASS_4A",
    "5": "CLASS_5",
    "class 5": "CLASS_5",
    "class_5": "CLASS_5",
    "5b": "CLASS_5B",
    "class 5b": "CLASS_5B",
    "class_5b": "CLASS_5B",
    "5a": "CLASS_5A",
    "class 5a": "CLASS_5A",
    "class_5a": "CLASS_5A",
}


def normalize_ap_acf_class(value: Any) -> str | None:
    if value is None:
        return None
    raw = str(value).strip().lower()
    if raw.upper() in AP_ACF_CLASSES:
        return raw.upper()
    return CLASS_ALIASES.get(raw)


def get_class_profile(ap_acf_class: str | None) -> Dict[str, Any] | None:
    if ap_acf_class is None:
        return None
    return AP_ACF_CLASSES.get(ap_acf_class)


def derive_subclass(ap_acf_class: str | None) -> str:
    if not ap_acf_class:
        return "UNDECLARED"
    if ap_acf_class.endswith("A"):
        return "AUTONOMOUS"
    if ap_acf_class.endswith("B"):
        return "BOUNDED"
    return "STANDARD"


def derive_pipeline_mode_from_class(ap_acf_class: str | None, threshold_tier: str | None) -> str:
    profile = get_class_profile(ap_acf_class)
    if profile is None:
        return "MODE_1_FULL_MIRRORED"
    if profile["risk_level"] >= 5 or threshold_tier == "TOP":
        return "MODE_1_FULL_MIRRORED"
    if profile["risk_level"] >= 3 or threshold_tier == "MEDIUM":
        return "MODE_2_SPLIT_VALIDATOR"
    return "MODE_3_SINGLE_CONSTRAINED"
    
