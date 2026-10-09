import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlencode
from typing import Dict, Any, List, Optional, Set, Tuple


def un_defang(val: Optional[str]) -> Optional[str]:
    """Strip standard forensic defanging wrappers (hxxp -> http, [.] -> ., [:] -> :)."""
    if not val or not isinstance(val, str):
        return None
    cleaned = val.strip()
    # Replace hxxp / hxxps / fxp
    cleaned = re.sub(
        r"^hxxps?://",
        lambda m: "https://" if m.group(0).lower().startswith("hxxps") else "http://",
        cleaned,
        flags=re.IGNORECASE
    )
    cleaned = re.sub(r"^fxps?://", "ftp://", cleaned, flags=re.IGNORECASE)
    # Replace brackets around dots, colons
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    cleaned = cleaned.replace("[:]", ":").replace("(:)", ":").replace("{:}", ":")
    # Strip any enclosing quotation or angle brackets
    cleaned = cleaned.strip("\"'<>")
    return cleaned.strip() or None


def normalize_url(raw_url: Optional[str]) -> Optional[str]:
    """Normalize a URL for reliable forensic comparison across evidence records."""
    if not raw_url or not isinstance(raw_url, str):
        return None
    val = un_defang(raw_url)
    if not val:
        return None

    # Ensure scheme
    if not val.startswith("http://") and not val.startswith("https://"):
        val = "http://" + val

    try:
        parsed = urlparse(val)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Remove default ports
        if ":" in netloc:
            # Check if netloc is IPv6 enclosed in brackets
            if netloc.startswith("[") and "]:" in netloc:
                host_part, port = netloc.rsplit(":", 1)
                if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                    netloc = host_part
            elif not netloc.startswith("["):
                host, port = netloc.split(":", 1)
                if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                    netloc = host

        # Normalize path: remove redundant trailing slash unless root
        path = parsed.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]

        # Normalize query: sort parameters, ignore fragment (client-side only)
        query = ""
        if parsed.query:
            params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
            query = "?" + urlencode(params)

        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return raw_url.strip().lower()


def normalize_domain(raw_domain: Optional[str]) -> Optional[str]:
    """Normalize a domain name (lowercase, strip whitespace, defang, remove trailing dot and protocol)."""
    if not raw_domain or not isinstance(raw_domain, str):
        return None
    val = un_defang(raw_domain)
    if not val:
        return None
    clean = val.strip().lower().rstrip(".")
    if not clean:
        return None
    # Strip protocol if accidentally included
    if clean.startswith("http://") or clean.startswith("https://"):
        try:
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        except Exception:
            pass
    # Strip port if present
    if ":" in clean and not clean.startswith("["):
        clean = clean.split(":")[0]
    return clean.strip().rstrip(".") or None


def extract_apex_domain(domain: Optional[str]) -> Optional[str]:
    """Extract approximate root/apex domain (e.g., sub.example.com -> example.com)."""
    norm = normalize_domain(domain)
    if not norm:
        return None
    parts = norm.split(".")
    if len(parts) >= 2:
        # Common two-part ccTLDs
        two_part_tlds = {
            "co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "gov.in",
            "co.in", "ac.in", "com.br", "co.jp", "com.sg", "co.nz"
        }
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return norm


def normalize_ip(raw_ip: Optional[str]) -> Optional[Tuple[str, bool]]:
    """Parse and normalize IPv4/IPv6 address. Strips ports and handles defanging.
    Returns (canonical_ip_str, is_private_or_internal).
    """
    if not raw_ip or not isinstance(raw_ip, str):
        return None
    val = un_defang(raw_ip)
    if not val:
        return None
    val = val.strip()

    # Strip bracketed IPv6 formatting e.g. [2001:db8::1] or [2001:db8::1]:8080
    if val.startswith("[") and "]" in val:
        close_bracket = val.index("]")
        val = val[1:close_bracket]
    elif ":" in val and "." in val:
        # IPv4 with port e.g. 192.168.1.1:8080
        val = val.split(":")[0]

    try:
        ip_obj = ipaddress.ip_address(val)
        is_private = (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
        ) and not (
            val.startswith("198.51.100.") or val.startswith("203.0.113.") or val.startswith("192.0.2.")
        )
        return (str(ip_obj), is_private)
    except ValueError:
        return None


def normalize_hash(raw_hash: Optional[str]) -> Optional[str]:
    """Validate and normalize a cryptographic hash (MD5 32, SHA-1 40, SHA-256 64 hex chars)."""
    if not raw_hash or not isinstance(raw_hash, str):
        return None
    val = raw_hash.strip().lower()
    if len(val) in (32, 40, 64) and re.match(r"^[0-9a-f]+$", val):
        return val
    return None


def extract_cves(text: Optional[str]) -> List[str]:
    """Extract referenced CVE identifiers from findings or notes."""
    if not text or not isinstance(text, str):
        return []
    matches = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)
    return sorted(list(set(m.upper() for m in matches)))


def extract_file_info(raw_val: Optional[str], findings: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Extract filename and extension from URL, file path, input, or findings."""
    candidates = []
    if raw_val and isinstance(raw_val, str):
        # If URL, check path
        if "/" in raw_val:
            path_part = raw_val.split("?")[0].split("#")[0].rstrip("/")
            base = path_part.split("/")[-1]
            if "." in base and not re.match(r"^\d+\.\d+\.\d+\.\d+$", base):
                candidates.append(base)
        elif "." in raw_val and not re.match(r"^\d+\.\d+\.\d+\.\d+$", raw_val):
            ext = raw_val.rsplit(".", 1)[-1].lower()
            if ext in {
                "exe", "dll", "bin", "pdf", "zip", "tar", "gz", "7z", "rar",
                "sh", "py", "ps1", "bat", "vbs", "js", "doc", "docx", "xls",
                "xlsx", "apk", "elf", "iso", "img", "vmdk", "lnk", "hta"
            }:
                candidates.append(raw_val)

    if findings and isinstance(findings, str):
        matches = re.findall(
            r"\b([a-zA-Z0-9_\-\.]+\.(?:exe|dll|bin|pdf|zip|tar|gz|7z|rar|sh|py|ps1|bat|vbs|js|doc[x]?|xls[x]?|apk|elf|iso|img|vmdk|lnk|hta))\b",
            findings,
            re.IGNORECASE
        )
        candidates.extend(matches)

    for c in candidates:
        clean = c.strip().strip("\"'<>")
        if clean and "." in clean:
            ext = clean.rsplit(".", 1)[-1].lower()
            if ext in {
                "exe", "dll", "bin", "pdf", "zip", "tar", "gz", "7z", "rar",
                "sh", "py", "ps1", "bat", "vbs", "js", "doc", "docx", "xls",
                "xlsx", "apk", "elf", "iso", "img", "vmdk", "lnk", "hta"
            }:
                return (clean.lower(), f".{ext}")
    return (None, None)


def extract_user_ids(text: Optional[str]) -> List[str]:
    """Extract user or account identities mentioned in input or findings."""
    if not text or not isinstance(text, str):
        return []
    users = set()
    matches = re.findall(r"(?:user|account|username|login)[:=]\s*([a-zA-Z0-9_\-\.]{2,30})", text, re.IGNORECASE)
    for m in matches:
        m_clean = m.strip().lower()
        if m_clean not in {"true", "false", "null", "none", "admin_role", "password", "test"}:
            users.add(m_clean)
    domain_users = re.findall(r"\b([A-Za-z0-9_]{2,15}\\[A-Za-z0-9_\.\-]{2,25})\b", text)
    for du in domain_users:
        users.add(du.lower())
    return sorted(list(users))


def extract_device_ids(text: Optional[str]) -> List[str]:
    """Extract host, workstation, or machine identifiers mentioned in input or findings."""
    if not text or not isinstance(text, str):
        return []
    devs = set()
    matches = re.findall(r"\b((?:WORKSTATION|DESKTOP|LAPTOP|SRV|SERVER|DC)-[A-Za-z0-9_\-]{2,20})\b", text, re.IGNORECASE)
    for m in matches:
        devs.add(m.upper())
    host_matches = re.findall(r"(?:host|hostname|machine|device)[:=]\s*([a-zA-Z0-9_\-]{3,30})", text, re.IGNORECASE)
    for hm in host_matches:
        devs.add(hm.upper())
    mac_matches = re.findall(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", text)
    for mac in mac_matches:
        devs.add(mac.upper())
    return sorted(list(devs))


def get_ipv4_subnet24(ip_str: Optional[str]) -> Optional[str]:
    """Compute /24 subnet for IPv4 address if public."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4 and not ip_obj.is_private and not ip_obj.is_loopback:
            network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(network)
    except ValueError:
        pass
    return None


def extract_indicators_from_evidence(evidence_obj: Any) -> Dict[str, Any]:
    """Extract and normalize all available indicators from an Evidence model or dict."""
    if hasattr(evidence_obj, "__table__"):
        ev_id = getattr(evidence_obj, "evidence_id", "")
        input_val = getattr(evidence_obj, "input_value", "")
        input_type = getattr(evidence_obj, "input_type", "")
        url_val = getattr(evidence_obj, "url", None)
        domain_val = getattr(evidence_obj, "domain", None)
        ip_val = getattr(evidence_obj, "ip_address", None)
        sha256_val = getattr(evidence_obj, "sha256_hash", None)
        findings_val = getattr(evidence_obj, "findings", "") or ""
        risk_score = float(getattr(evidence_obj, "risk_score", 0.0) or 0.0)
        risk_level = getattr(evidence_obj, "risk_level", "LOW")
        ts = getattr(evidence_obj, "timestamp", None)
    elif isinstance(evidence_obj, dict):
        ev_id = evidence_obj.get("evidence_id", "")
        input_val = evidence_obj.get("input_value") or evidence_obj.get("input") or ""
        input_type = evidence_obj.get("input_type", "")
        url_val = evidence_obj.get("url")
        domain_val = evidence_obj.get("domain")
        ip_val = evidence_obj.get("ip_address")
        sha256_val = evidence_obj.get("sha256_hash")
        findings_val = evidence_obj.get("findings", "") or ""
        risk_score = float(evidence_obj.get("risk_score", 0.0) or 0.0)
        risk_level = evidence_obj.get("risk_level", "LOW")
        ts = evidence_obj.get("timestamp")
    else:
        return {}

    combined_text = f"{input_val} {findings_val}"
    file_name, file_ext = extract_file_info(input_val or url_val, findings_val)
    users = extract_user_ids(combined_text)
    devices = extract_device_ids(combined_text)

    # Extract Case / Event associations
    cases_val = []
    if hasattr(evidence_obj, "cases") and getattr(evidence_obj, "cases"):
        cases_val = list(getattr(evidence_obj, "cases"))
    elif isinstance(evidence_obj, dict):
        if evidence_obj.get("cases"):
            cases_val = list(evidence_obj.get("cases"))
        elif evidence_obj.get("case_ids"):
            cases_val = list(evidence_obj.get("case_ids"))
        elif evidence_obj.get("case_id"):
            cases_val = [evidence_obj.get("case_id")]
    if hasattr(evidence_obj, "case_id") and getattr(evidence_obj, "case_id"):
        cid = getattr(evidence_obj, "case_id")
        if cid and cid not in cases_val:
            cases_val.append(cid)

    indicators: Dict[str, Any] = {
        "evidence_id": ev_id,
        "input_value": input_val,
        "input_type": input_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings_val,
        "timestamp": ts,
        "url": None,
        "domain": None,
        "apex_domain": None,
        "ip": None,
        "is_private_ip": False,
        "sha256": None,
        "file_name": file_name,
        "file_ext": file_ext,
        "users": users,
        "devices": devices,
        "subnet24": None,
        "cves": extract_cves(findings_val),
        "cases": cases_val,
    }

    # Extract URL
    target_url = url_val if url_val else (input_val if input_type == "url" else None)
    if target_url:
        norm_url = normalize_url(target_url)
        indicators["url"] = norm_url
        if norm_url:
            try:
                parsed = urlparse(norm_url)
                if parsed.hostname:
                    ip_norm = normalize_ip(parsed.hostname)
                    if ip_norm:
                        indicators["ip"] = ip_norm[0]
                        indicators["is_private_ip"] = ip_norm[1]
                    else:
                        norm_dom = normalize_domain(parsed.hostname)
                        indicators["domain"] = norm_dom
                        indicators["apex_domain"] = extract_apex_domain(norm_dom)
            except Exception:
                pass

    # Extract Domain
    target_dom = domain_val if domain_val else (input_val if input_type == "domain" else None)
    if target_dom and not indicators["domain"]:
        norm_dom = normalize_domain(target_dom)
        indicators["domain"] = norm_dom
        indicators["apex_domain"] = extract_apex_domain(norm_dom)

    # Extract IP
    target_ip = ip_val if ip_val else (input_val if input_type == "ip" else None)
    if target_ip and not indicators["ip"]:
        ip_norm = normalize_ip(target_ip)
        if ip_norm:
            indicators["ip"] = ip_norm[0]
            indicators["is_private_ip"] = ip_norm[1]

    # IP fallback extraction from findings context if not yet discovered
    if not indicators["ip"] and findings_val:
        ip_candidates = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", findings_val)
        for cand in ip_candidates:
            cand_norm = normalize_ip(cand)
            if cand_norm:
                indicators["ip"] = cand_norm[0]
                indicators["is_private_ip"] = cand_norm[1]
                break

    # Calculate Subnet /24 for public IPs
    if indicators["ip"] and not indicators["is_private_ip"]:
        indicators["subnet24"] = get_ipv4_subnet24(indicators["ip"])

    # Extract Hash
    target_hash = sha256_val if sha256_val else (input_val if input_type in ("hash", "sha256") else None)
    norm_h = normalize_hash(target_hash)
    if norm_h:
        indicators["sha256"] = norm_h
    elif not indicators["sha256"] and combined_text:
        hash_matches = re.findall(r"\b([0-9a-fA-F]{64})\b", combined_text)
        for hm in hash_matches:
            hm_norm = normalize_hash(hm)
            if hm_norm:
                indicators["sha256"] = hm_norm
                break

    return indicators


def format_time_delta(dt1: Optional[datetime], dt2: Optional[datetime]) -> Tuple[Optional[float], Optional[str]]:
    """Calculate delta between two timestamps and format human-readable duration."""
    if not dt1 or not dt2:
        return (None, None)
    try:
        if isinstance(dt1, str):
            dt1 = datetime.fromisoformat(dt1.replace("Z", "+00:00"))
        if isinstance(dt2, str):
            dt2 = datetime.fromisoformat(dt2.replace("Z", "+00:00"))

        if dt1.tzinfo is None:
            dt1 = dt1.replace(tzinfo=timezone.utc)
        if dt2.tzinfo is None:
            dt2 = dt2.replace(tzinfo=timezone.utc)

        delta = abs((dt1 - dt2).total_seconds())
        if delta < 60:
            human = f"{int(delta)} seconds apart"
        elif delta < 3600:
            mins = int(delta / 60)
            human = f"{mins} minute{'s' if mins != 1 else ''} apart"
        elif delta < 86400:
            hrs = round(delta / 3600, 1)
            human = f"{hrs} hour{'s' if hrs != 1 else ''} apart"
        else:
            days = round(delta / 86400, 1)
            human = f"{days} day{'s' if days != 1 else ''} apart"
        return (delta, human)
    except Exception:
        return (None, None)


def correlate_records(
    evidence_list: List[Any],
    target_evidence_id: Optional[str] = None
) -> Dict[str, Any]:
    """Execute cross-evidence correlation across all provided evidence records.

    Forensic rigor principles:
    1. Compares only indicators actually present in the evidence.
    2. Avoids linking a record to itself (i != j) and avoids duplicate relationships.
    3. Prevents derivative double-counting (e.g. an exact URL match is not falsely counted as
       a multi-indicator convergence merely because it also contains its own domain).
    4. Categorizes relationships:
       - EXACT_MATCH: Single technical indicator match (Hash, URL, Domain, IP, File Name, User, Device).
       - MULTI_INDICATOR: Convergence across 2+ independent indicator types.
       - TEMPORAL_RELATIONSHIP: Events co-occurring within short temporal windows or 24h high-risk co-occurrence.
       - UNCONFIRMED_HYPOTHESIS: Shared apex domain, private non-routable IPs, or adjacent /24 subnet blocks.
    5. Accompanies all findings with strict forensic caveats regarding CDNs, dynamic IPs, and attribution limits.
    6. Generates beginner-friendly simple explanations and actionable next steps for investigators.
    """
    extracted_records: List[Dict[str, Any]] = []
    for item in evidence_list:
        data = extract_indicators_from_evidence(item)
        if (
            data
            and data.get("evidence_id")
            and (
                data.get("url")
                or data.get("domain")
                or data.get("ip")
                or data.get("sha256")
                or data.get("file_name")
                or data.get("users")
                or data.get("devices")
                or data.get("cves")
                or (data.get("input_value") and data.get("input_value").strip())
            )
        ):
            extracted_records.append(data)

    total_records = len(extracted_records)
    correlations: List[Dict[str, Any]] = []
    seen_pairs: Set[str] = set()

    for i in range(total_records):
        for j in range(i + 1, total_records):
            rec_a = extracted_records[i]
            rec_b = extracted_records[j]

            id_a = rec_a["evidence_id"]
            id_b = rec_b["evidence_id"]

            # Filter if target_evidence_id is specified
            if target_evidence_id and target_evidence_id not in (id_a, id_b):
                continue

            # Ensure canonical pair key to guarantee no duplicates
            pair_key = f"{min(id_a, id_b)}<->{max(id_a, id_b)}"
            if pair_key in seen_pairs:
                continue

            # Evaluate indicators
            matched_indicators: List[Dict[str, Any]] = []
            hypotheses: List[Dict[str, Any]] = []
            independent_indicator_types: Set[str] = set()

            # 1. File Hash match (highest cryptographic certainty)
            if rec_a["sha256"] and rec_b["sha256"] and rec_a["sha256"] == rec_b["sha256"]:
                matched_indicators.append({
                    "indicator_type": "sha256",
                    "matched_value": rec_a["sha256"],
                    "is_private_or_shared": False,
                    "details": "Cryptographic SHA-256 hash match: bit-for-bit identical digital artifact content."
                })
                independent_indicator_types.add("SHA256")

            # 2. Exact URL match
            exact_url_matched = False
            if rec_a["url"] and rec_b["url"] and rec_a["url"] == rec_b["url"]:
                exact_url_matched = True
                matched_indicators.append({
                    "indicator_type": "url",
                    "matched_value": rec_a["url"],
                    "is_private_or_shared": False,
                    "details": "Exact normalized URL match: both items target the identical web resource."
                })
                independent_indicator_types.add("URL")

            # 3. Domain match (avoid derivative double counting if exact URL already matched)
            if rec_a["domain"] and rec_b["domain"] and rec_a["domain"] == rec_b["domain"]:
                if not exact_url_matched:
                    matched_indicators.append({
                        "indicator_type": "domain",
                        "matched_value": rec_a["domain"],
                        "is_private_or_shared": False,
                        "details": f"Exact domain match '{rec_a['domain']}': both records target identical domain infrastructure."
                    })
                    independent_indicator_types.add("DOMAIN")
            elif rec_a["apex_domain"] and rec_b["apex_domain"] and rec_a["apex_domain"] == rec_b["apex_domain"]:
                hypotheses.append({
                    "indicator_type": "apex_domain_cluster",
                    "matched_value": rec_a["apex_domain"],
                    "is_private_or_shared": False,
                    "details": f"Shared apex domain '{rec_a['apex_domain']}' with distinct subdomains ('{rec_a.get('domain')}' vs '{rec_b.get('domain')}')."
                })

            # 4. Exact IP match
            if rec_a["ip"] and rec_b["ip"] and rec_a["ip"] == rec_b["ip"]:
                is_internal = rec_a["is_private_ip"] or rec_b["is_private_ip"]
                matched_indicators.append({
                    "indicator_type": "ip",
                    "matched_value": rec_a["ip"],
                    "is_private_or_shared": is_internal,
                    "details": "Exact IP match: records reference identical IP address." + (
                        " (RFC 1918 / Loopback non-routable address - common across independent local networks)"
                        if is_internal else
                        " (Public routable address)"
                    )
                })
                if not is_internal:
                    independent_indicator_types.add("IP")
            elif (
                rec_a["subnet24"]
                and rec_b["subnet24"]
                and rec_a["subnet24"] == rec_b["subnet24"]
                and rec_a["ip"] != rec_b["ip"]
            ):
                # Subnet /24 Proximity Cluster
                hypotheses.append({
                    "indicator_type": "subnet_cluster",
                    "matched_value": rec_a["subnet24"],
                    "is_private_or_shared": False,
                    "details": f"Subnet /24 proximity: Both public IPs ({rec_a['ip']} and {rec_b['ip']}) reside in adjacent CIDR network block {rec_a['subnet24']}."
                })

            # 5. Shared File Name Match (avoid derivative double counting if exact URL already matched)
            if not exact_url_matched and rec_a["file_name"] and rec_b["file_name"] and rec_a["file_name"] == rec_b["file_name"]:
                matched_indicators.append({
                    "indicator_type": "file_name",
                    "matched_value": rec_a["file_name"],
                    "is_private_or_shared": False,
                    "details": f"Matching filename '{rec_a['file_name']}' referenced across artifacts."
                })
                independent_indicator_types.add("FILE_NAME")

            # 6. Shared User Account Identifiers
            shared_users = set(rec_a.get("users", [])) & set(rec_b.get("users", []))
            for u in sorted(list(shared_users)):
                matched_indicators.append({
                    "indicator_type": "user_identifier",
                    "matched_value": u,
                    "is_private_or_shared": False,
                    "details": f"Shared user account identifier '{u}' observed in artifact context."
                })
                independent_indicator_types.add("USER")

            # 7. Shared Device / Hostname Identifiers
            shared_devices = set(rec_a.get("devices", [])) & set(rec_b.get("devices", []))
            for d in sorted(list(shared_devices)):
                matched_indicators.append({
                    "indicator_type": "device_identifier",
                    "matched_value": d,
                    "is_private_or_shared": False,
                    "details": f"Shared host, machine, or MAC identifier '{d}'."
                })
                independent_indicator_types.add("DEVICE")

            # 8. Shared CVE references from analysis findings
            shared_cves = set(rec_a.get("cves", [])) & set(rec_b.get("cves", []))
            for cve in sorted(list(shared_cves)):
                matched_indicators.append({
                    "indicator_type": "cve_exploitation",
                    "matched_value": cve,
                    "is_private_or_shared": False,
                    "details": f"Shared vulnerability identifier '{cve}' noted in heuristic analysis findings."
                })
                independent_indicator_types.add("CVE")

            # 9. Shared Investigation Case / Related Event Records
            shared_cases = set(rec_a.get("cases", [])) & set(rec_b.get("cases", []))
            for c_id in sorted(list(shared_cases)):
                matched_indicators.append({
                    "indicator_type": "related_case_record",
                    "matched_value": c_id,
                    "is_private_or_shared": False,
                    "details": f"Both artifacts are co-investigated under formal investigation record '{c_id}'."
                })
                independent_indicator_types.add("CASE_RECORD")

            # Time delta calculation
            time_delta_sec, time_delta_str = format_time_delta(rec_a["timestamp"], rec_b["timestamp"])

            # Determine relationship type, confidence, rule, and explanations
            rel_type: str = ""
            confidence: str = ""
            rule_applied: str = ""
            simple_explanation: str = ""
            investigator_action: str = ""
            explanation: str = ""
            caveat: str = ""

            if len(independent_indicator_types) >= 2:
                # Multi-indicator relationship across distinct independent indicator categories
                rel_type = "MULTI_INDICATOR"
                confidence = "HIGH"
                rule_applied = "MULTI_INDICATOR_CONVERGENCE"
                ind_list = sorted(list(independent_indicator_types))
                explanation = (
                    f"Strong multi-indicator convergence: Records share {len(ind_list)} distinct independent indicator types "
                    f"({', '.join(ind_list)}). Evidence items: '{rec_a['input_value']}' and '{rec_b['input_value']}'."
                )
                simple_explanation = (
                    f"Strong evidence overlap: these two records share multiple distinct digital clues ({', '.join(ind_list)}). "
                    "This strongly indicates they belong to the same campaign, server setup, or user session."
                )
                investigator_action = (
                    "Correlate firewall and DNS logs during this timeframe to map out the complete infection timeline."
                )
                caveat = (
                    "Forensic Assessment: Multiple overlapping technical indicators provide high correlation confidence. "
                    "However, investigator verification of passive DNS historical timelines and hosting architecture is recommended before attributing to a single threat actor."
                )

            elif len(matched_indicators) >= 1:
                # Single exact indicator match or primary indicator match
                non_priv = [m for m in matched_indicators if not m.get("is_private_or_shared")]
                match_item = non_priv[0] if non_priv else matched_indicators[0]
                m_type = match_item["indicator_type"]
                m_val = match_item["matched_value"]

                if match_item["is_private_or_shared"]:
                    rel_type = "UNCONFIRMED_HYPOTHESIS"
                    confidence = "LOW"
                    rule_applied = "RFC1918_PRIVATE_IP_HYPOTHESIS"
                    explanation = (
                        f"Overlapping private/internal IP address '{m_val}'. Both records refer to RFC 1918 or loopback addresses."
                    )
                    simple_explanation = (
                        f"Both records mention private internal IP address '{m_val}'. "
                        "Because internal IPs like 192.168.x.x are reused across millions of homes and offices, this cannot prove the events are related without network lease logs."
                    )
                    investigator_action = (
                        "Obtain DHCP server lease logs for this exact timestamp to see which physical computer had this internal IP."
                    )
                    caveat = (
                        "Forensic Assessment (Critical): A shared private or internal IP address (RFC 1918 / 127.0.0.1) "
                        "MUST NOT be used as proof of correlation or attribution. These non-routable addresses are standard across millions of distinct local networks."
                    )
                else:
                    rel_type = "EXACT_MATCH"
                    confidence = "HIGH" if m_type in ("sha256", "url") else "MEDIUM"
                    explanation = (
                        f"Exact technical indicator match on {m_type.upper()}: '{m_val}'. "
                        f"Found in both Evidence {id_a[:8]} and {id_b[:8]}."
                    )

                    if m_type == "sha256":
                        rule_applied = "CRYPTOGRAPHIC_FILE_MATCH"
                        simple_explanation = (
                            "Both evidence items have the exact same digital fingerprint (SHA-256). "
                            "This mathematically proves that both records involve identical file contents or binaries."
                        )
                        investigator_action = (
                            "Check computer file systems to see how and where this specific file was written or executed."
                        )
                        caveat = "Forensic Assessment: Cryptographic artifact match verifies identical digital data."
                    elif m_type == "url":
                        rule_applied = "SHARED_URL_RESOURCE"
                        simple_explanation = (
                            "Both evidence items point to the exact same web address or download link."
                        )
                        investigator_action = (
                            "Check proxy logs to see if anyone clicked on this URL or downloaded content from it."
                        )
                        caveat = (
                            "Forensic Assessment: Exact URL match demonstrates identical resource targeting. "
                            "Confirm timestamps and HTTP parameters to distinguish between automated scanning, campaign re-use, and legitimate web service interaction."
                        )
                    elif m_type == "domain":
                        rule_applied = "SHARED_DOMAIN_INFRASTRUCTURE"
                        simple_explanation = (
                            f"Both items communicate with the exact same domain name ('{m_val}')."
                        )
                        investigator_action = (
                            "Look up domain registration (WHOIS) and passive DNS records to see when it was registered and where it pointed."
                        )
                        caveat = (
                            "Forensic Assessment: Exact domain match indicates shared infrastructure reference. "
                            "However, domain ownership history, sinkholing, or compromise of legitimate subdomains should be verified before confirming single-campaign attribution."
                        )
                    elif m_type == "ip":
                        rule_applied = "SHARED_PUBLIC_IP"
                        simple_explanation = (
                            f"Both items involve the same public IP address ('{m_val}'). "
                            "Keep in mind that many different websites often share the same server or cloud provider."
                        )
                        investigator_action = (
                            "Check if this IP belongs to a shared cloud hosting provider (e.g. Cloudflare, AWS) or a dedicated server."
                        )
                        caveat = (
                            "Forensic Assessment (Critical): A shared IP address alone MUST NOT be described as proof that two records "
                            "belong to the same threat actor or campaign. Public IP addresses are frequently shared across benign and malicious services via "
                            "shared web hosting, cloud CDNs (e.g., Cloudflare, Akamai), multi-tenant load balancers, or VPN exit points."
                        )
                    elif m_type == "file_name":
                        rule_applied = "SHARED_FILE_NAME_ARTIFACT"
                        simple_explanation = (
                            f"Both records reference a file with the identical name '{m_val}'."
                        )
                        investigator_action = (
                            "Compute file hashes to confirm if the files are truly identical or just share the same filename."
                        )
                        caveat = (
                            "Forensic Assessment: Matching filenames indicate potential payload reuse, but distinct files can share identical common names."
                        )
                    elif m_type == "user_identifier":
                        rule_applied = "SHARED_USER_ACCOUNT"
                        simple_explanation = (
                            f"Both events involve user account '{m_val}'."
                        )
                        investigator_action = (
                            "Review authentication logs to see if this user account was used from multiple locations."
                        )
                        caveat = (
                            "Forensic Assessment: Shared user account suggests account compromise or common operator."
                        )
                    elif m_type == "device_identifier":
                        rule_applied = "SHARED_DEVICE_AFFINITY"
                        simple_explanation = (
                            f"Both events occurred on or involve device '{m_val}'."
                        )
                        investigator_action = (
                            "Isolate the machine and perform endpoint forensic collection (RAM and disk triage)."
                        )
                        caveat = (
                            "Forensic Assessment: Common device indicator links activity to the same endpoint hardware or VM."
                        )
                    elif m_type == "related_case_record":
                        rule_applied = "CO_INVESTIGATED_EVENT_RECORD"
                        simple_explanation = (
                            f"Both evidence items belong to the same investigation case ('{m_val}')."
                        )
                        investigator_action = (
                            "Review case timeline and interview records to correlate how both artifacts were acquired."
                        )
                        caveat = (
                            "Forensic Assessment: Association within the same investigation case reflects investigator scoping, "
                            "not automatic proof of common threat actor origin."
                        )
                    else:
                        rule_applied = "EXACT_INDICATOR_MATCH"
                        simple_explanation = f"Exact match on indicator: {m_val}."
                        investigator_action = "Review raw forensic records."
                        caveat = "Forensic Assessment: Single indicator match requires corroboration."

            elif hypotheses:
                # Unconfirmed hypothesis (e.g., shared apex domain or subnet cluster)
                rel_type = "UNCONFIRMED_HYPOTHESIS"
                confidence = "LOW"
                hypo = hypotheses[0]
                matched_indicators = hypotheses

                if hypo["indicator_type"] == "apex_domain_cluster":
                    rule_applied = "SHARED_APEX_DOMAIN_CLUSTER"
                    explanation = (
                        f"Possible organizational or infrastructure clustering: Both records reference subdomains under apex domain '{hypo['matched_value']}'. "
                        f"Evidence {id_a[:8]} uses '{rec_a.get('domain')}', whereas Evidence {id_b[:8]} uses '{rec_b.get('domain')}'."
                    )
                    simple_explanation = (
                        f"Both websites share the same root domain ('{hypo['matched_value']}'), but have different subdomains. "
                        "They could be operated by the same person, or hosted on a public service where anyone can register subdomains."
                    )
                    investigator_action = (
                        "Check if the root domain is a free subdomain provider (like duckdns.org) or a private domain."
                    )
                    caveat = (
                        "Forensic Assessment: Shared apex domain represents an unconfirmed hypothesis. "
                        "Attribution requires confirming whether the apex domain is a dynamic DNS service, free hosting provider, or dedicated actor infrastructure."
                    )
                else:
                    rule_applied = "SUBNET_PROXIMITY_CLUSTER"
                    explanation = (
                        f"Network proximity hypothesis: Both public IPs reside in adjacent /24 subnet block '{hypo['matched_value']}'."
                    )
                    simple_explanation = (
                        f"Both servers have IP addresses in the same small network block ({hypo['matched_value']}). "
                        "Threat actors often rent several neighboring IP addresses in the same data center."
                    )
                    investigator_action = (
                        "Look up the Autonomous System Number (ASN) and hosting company to see if both servers share the same data center."
                    )
                    caveat = (
                        "Forensic Assessment: Subnet proximity indicates shared hosting provider or colocation, but does not prove single-operator attribution."
                    )

            elif time_delta_sec is not None and time_delta_sec <= 86400 and (
                rec_a["risk_level"] == "HIGH" and rec_b["risk_level"] == "HIGH"
            ):
                # Temporal relationship within 24 hours between high-risk events
                rel_type = "TEMPORAL_RELATIONSHIP"
                confidence = "INFORMATIONAL"
                rule_applied = "TEMPORAL_BURST_PROXIMITY" if time_delta_sec <= 300 else "TEMPORAL_WINDOW_CO_OCCURRENCE"
                matched_indicators = [{
                    "indicator_type": "temporal_window",
                    "matched_value": f"{time_delta_str}",
                    "is_private_or_shared": False,
                    "details": f"Both high-risk incidents occurred within {time_delta_str}."
                }]
                explanation = (
                    f"Temporal co-occurrence: Both high-risk artifacts were recorded within {time_delta_str} "
                    f"('{rec_a['input_value']}' and '{rec_b['input_value']}')."
                )
                simple_explanation = (
                    f"These two high-risk events happened close together in time ({time_delta_str}). "
                    "In cyber security, multiple attacks within a short window may be part of the same coordinated incident, but could also be unrelated automated scanners."
                )
                investigator_action = (
                    "Build a complete incident timeline to verify the exact order of events and check for connecting log records."
                )
                caveat = (
                    "Forensic Assessment: Temporal proximity alone does NOT establish common origin. "
                    "Concurrent security incidents frequently occur from independent automated crawlers or unrelated threat actors operating during the same timeframe."
                )
            else:
                # No meaningful correlation found
                continue

            seen_pairs.add(pair_key)
            correlations.append({
                "relationship_id": f"rel-{len(correlations) + 1:03d}",
                "source_evidence_id": id_a,
                "target_evidence_id": id_b,
                "source_input": rec_a["input_value"],
                "target_input": rec_b["input_value"],
                "source_risk_level": rec_a["risk_level"],
                "target_risk_level": rec_b["risk_level"],
                "relationship_type": rel_type,
                "confidence_level": confidence,
                "rule_applied": rule_applied,
                "matched_indicators": matched_indicators,
                "time_delta_seconds": time_delta_sec,
                "time_delta_human": time_delta_str,
                "simple_explanation": simple_explanation,
                "investigator_action": investigator_action,
                "explanation": explanation,
                "forensic_caveat": caveat,
            })

    # Summary statistics
    type_counts: Dict[str, int] = {}
    for c in correlations:
        t = c["relationship_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "total_records_analyzed": total_records,
        "total_correlations_found": len(correlations),
        "relationship_type_counts": type_counts,
        "correlations": correlations,
    }


