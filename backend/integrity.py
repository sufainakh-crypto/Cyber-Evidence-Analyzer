import json
import hashlib
from typing import Dict, Any, Optional

PROTECTED_FIELDS = [
    "evidence_id",
    "input_value",
    "input_type",
    "risk_score",
    "risk_level",
    "timestamp",
]

DISCLAIMER_TEXT = (
    "Cryptographic integrity verification confirms whether the protected evidence record "
    "matches its exact state at creation time. It does NOT verify the external truthfulness "
    "of the input data, nor does it guarantee legal admissibility in a court of law."
)


def _normalize_timestamp(val: Any) -> str:
    if val is None:
        return ""
    if hasattr(val, "strftime"):
        if hasattr(val, "tzinfo") and val.tzinfo is not None:
            try:
                from datetime import timezone
                val = val.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                pass
        return val.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(val, str):
        s = val.strip().replace(" ", "T")
        if "+" in s:
            s = s.split("+")[0]
        if s.endswith("Z"):
            s = s[:-1]
        if "." in s:
            s = s.split(".")[0]
        return s + "Z"
    return str(val)


def serialize_canonical(data: Dict[str, Any]) -> str:
    """Create a deterministic canonical JSON string of the protected evidence fields.
    
    Keys are strictly sorted, floats are rounded to 1 decimal place,
    timestamps are converted to normalized ISO strings, and whitespace is normalized.
    """
    canonical_dict = {}
    for key in PROTECTED_FIELDS:
        val = data.get(key)
        if key == "risk_score" and val is not None:
            val = round(float(val), 1)
        elif key == "timestamp":
            val = _normalize_timestamp(val)
        elif val is None:
            val = ""
        else:
            val = str(val)
        canonical_dict[key] = val

    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))


def compute_evidence_hash(data: Dict[str, Any]) -> str:
    """Compute SHA-256 hash over canonical representation of protected fields."""
    canonical_str = serialize_canonical(data)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def verify_evidence_hash(stored_hash: Optional[str], current_data: Dict[str, Any]) -> Dict[str, Any]:
    """Verify integrity of an evidence record against its stored SHA-256 hash.
    
    Status values:
    - VERIFIED: Hashes match exactly
    - INTEGRITY_MISMATCH: Protected fields have mutated or been tampered with
    - UNHASHED_LEGACY: Record was created before integrity hashing was introduced
    """
    if not stored_hash:
        return {
            "status": "UNHASHED_LEGACY",
            "matches": False,
            "stored_hash": None,
            "calculated_hash": compute_evidence_hash(current_data),
            "protected_fields": PROTECTED_FIELDS,
            "message": "Legacy evidence record created before cryptographic hash protection.",
            "disclaimer": DISCLAIMER_TEXT,
        }

    recalculated_hash = compute_evidence_hash(current_data)
    matches = (stored_hash.strip().lower() == recalculated_hash.strip().lower())

    status = "VERIFIED" if matches else "INTEGRITY_MISMATCH"
    msg = (
        "Evidence record verified. Cryptographic SHA-256 signature matches canonical fields."
        if matches
        else "INTEGRITY MISMATCH DETECTED: Protected evidence fields do not match the stored hash!"
    )

    return {
        "status": status,
        "matches": matches,
        "stored_hash": stored_hash,
        "calculated_hash": recalculated_hash,
        "protected_fields": PROTECTED_FIELDS,
        "message": msg,
        "disclaimer": DISCLAIMER_TEXT,
    }
