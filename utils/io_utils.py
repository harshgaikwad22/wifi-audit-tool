import json, csv, decimal
from datetime import datetime, timezone
UTC = timezone.utc


def write_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)

def sanitize(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    return obj

def write_csv(obj, filename):
    if not filename.endswith(".csv"):
        filename += ".csv"

    if isinstance(obj, dict):
        obj = [{**v, "BSSID": k} for k, v in obj.items()]

    if not obj:
        print("[!] No data to write.")
        return

    for entry in obj:
        rsn = entry.pop("RSN", None)
        if rsn:
            entry["RSN_version"] = rsn.get("version")
            entry["RSN_group_cipher"] = rsn.get("group_cipher")
            entry["RSN_pairwise_ciphers"] = ", ".join(rsn.get("pairwise_ciphers", []))
            entry["RSN_akm"] = ", ".join(rsn.get("akm", []))
            caps = rsn.get("rsn_capabilities")
            if caps:
                entry["RSN_MFPC"] = caps.get("MFPC")
                entry["RSN_MFPR"] = caps.get("MFPR")
        entry["first_seen"] = datetime.fromtimestamp(float(entry["first_seen"]), UTC).isoformat()

    with open(filename, "w", newline="") as csvfile:
        fieldnames = sorted(obj[0].keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for e in obj:
            writer.writerow(sanitize(e))
    print(f"[+] RSN info saved to {filename}")
