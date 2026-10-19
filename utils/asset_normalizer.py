SOURCE_LABELS = {
    "NESSUS_AGENT": "Nessus Agent",
    "NESSUS_SCAN": "Nessus Scan",
}

# Fallback when Tenable returns empty service_names (common for info-level port plugins).
WELL_KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6443: "Kubernetes API",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9100: "Printer",
}

SERVICE_ALIASES = {
    "www": "HTTP",
    "www-http": "HTTP",
    "http": "HTTP",
    "https": "HTTPS",
    "ssl": "HTTPS",
    "ssh": "SSH",
    "domain": "DNS",
    "dns": "DNS",
    "cifs": "SMB",
    "microsoft-ds": "SMB",
    "ms-wbt-server": "RDP",
    "snmp": "SNMP",
    "ldap": "LDAP",
    "smtp": "SMTP",
    "ftp": "FTP",
}


def _resolve_service(port_int: int, service_names: list) -> str:
    cleaned = [str(s).strip() for s in service_names if s and str(s).strip()]
    if cleaned:
        aliases = []
        for name in cleaned:
            aliases.append(SERVICE_ALIASES.get(name.lower(), name))
        known = WELL_KNOWN_SERVICES.get(port_int)
        if known and any(a.lower() in ("www", "http", "https", "ssl") for a in cleaned):
            if port_int in (80, 8080):
                return "HTTP" if port_int == 80 else known
            if port_int in (443, 8443):
                return "HTTPS" if port_int == 443 else known
        return ", ".join(dict.fromkeys(aliases))
    return WELL_KNOWN_SERVICES.get(port_int, "—")


def _is_v2_asset(asset):
    return bool(asset.get("timestamps") or asset.get("network"))


def _get_ipv4s(asset):
    network = asset.get("network") or {}
    if network.get("ipv4s"):
        return network["ipv4s"]
    return asset.get("ipv4s") or []


def _get_hostnames(asset):
    network = asset.get("network") or {}
    for key in ("hostnames", "fqdns"):
        if network.get(key):
            return network[key]
        if asset.get(key):
            return asset[key]
    if asset.get("netbios_names"):
        return asset["netbios_names"]
    return []


def _format_source_name(name):
    return SOURCE_LABELS.get(name, name.replace("_", " "))


def _get_exposure_score(raw):
    ratings = raw.get("ratings") or {}
    aes = ratings.get("aes") or {}
    if aes.get("score") is not None:
        return float(aes["score"])
    legacy = raw.get("exposure_score")
    if legacy is not None:
        return float(legacy)
    return None


def _normalize_open_ports(raw_ports):
    ports = []
    for entry in raw_ports or []:
        if not isinstance(entry, dict):
            continue
        port_num = entry.get("port")
        if port_num is None:
            continue
        try:
            port_int = int(port_num)
        except (TypeError, ValueError):
            continue
        service_names = entry.get("service_names") or []
        if isinstance(service_names, str):
            service_names = [service_names]
        service_names = [str(s) for s in service_names if s]
        protocol = (entry.get("protocol") or "").upper() or "—"
        ports.append({
            "port": port_int,
            "protocol": protocol,
            "service": _resolve_service(port_int, service_names),
            "serviceNames": service_names,
            "firstSeen": entry.get("first_seen"),
            "lastSeen": entry.get("last_seen"),
        })
    ports.sort(key=lambda p: (p["port"], p["protocol"]))
    return ports


def _get_raw_open_ports(raw):
    network = raw.get("network") or {}
    nested = network.get("open_ports")
    if nested:
        return nested
    return raw.get("open_ports") or []


def normalize_asset(raw):
    v2 = _is_v2_asset(raw)
    ipv4s = _get_ipv4s(raw)
    hostnames = _get_hostnames(raw)

    if v2:
        timestamps = raw.get("timestamps") or {}
        first_seen = timestamps.get("first_seen")
        last_seen = timestamps.get("last_seen")
    else:
        first_seen = raw.get("first_seen")
        last_seen = raw.get("last_seen")

    network = raw.get("network") or {}
    name = (
        (hostnames[0] if hostnames else None)
        or (network.get("fqdns") or [None])[0]
        or (raw.get("fqdns") or [None])[0]
        or (ipv4s[0] if ipv4s else None)
        or raw.get("id")
    )

    operating_systems = raw.get("operating_systems") or []
    sources = raw.get("sources") or []
    tags = raw.get("tags") or []
    open_ports = _normalize_open_ports(_get_raw_open_ports(raw))

    return {
        "id": raw.get("id"),
        "name": name,
        "ipAddress": ", ".join(ipv4s) if ipv4s else "—",
        "operatingSystem": ", ".join(operating_systems) if operating_systems else "—",
        "sources": ", ".join(_format_source_name(s.get("name", "")) for s in sources) or "—",
        "sourcesRaw": [s.get("name", "") for s in sources],
        "exposureScore": _get_exposure_score(raw),
        "tags": [
            {
                "uuid": t.get("uuid") or t.get("tag_uuid") or "",
                "key": t.get("key") or t.get("tag_key") or "",
                "value": t.get("value") or t.get("tag_value") or "",
                "label": (
                    f"{t.get('key') or t.get('tag_key', '')}: {t.get('value') or t.get('tag_value', '')}"
                    if (t.get("value") or t.get("tag_value"))
                    else (t.get("key") or t.get("tag_key") or "")
                ),
                "addedBy": t.get("added_by") or "",
                "addedAt": t.get("added_at") or "",
                "source": t.get("source") or "",
            }
            for t in tags
        ],
        "firstSeen": first_seen,
        "lastSeen": last_seen,
        "operatingSystemsRaw": operating_systems,
        "openPorts": open_ports,
    }


def normalize_assets(assets):
    return [normalize_asset(asset) for asset in assets]


def flatten_open_ports(assets):
    rows = []
    for asset in assets or []:
        sources_raw = asset.get("sourcesRaw") or []
        sources = asset.get("sources") or "—"
        for entry in asset.get("openPorts") or []:
            rows.append({
                "assetId": asset.get("id"),
                "name": asset.get("name") or "—",
                "ipAddress": asset.get("ipAddress") or "—",
                "port": entry.get("port"),
                "protocol": entry.get("protocol") or "—",
                "service": entry.get("service") or "—",
                "sources": sources,
                "sourcesRaw": sources_raw,
                "firstSeen": entry.get("firstSeen"),
                "lastSeen": entry.get("lastSeen"),
            })
    return rows
