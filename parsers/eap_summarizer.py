
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import EAPOL, EAP, Dot11

def eapol_summarizer(packets):
    clients = defaultdict(lambda: {
        "timestamps": [],
        "eap_identity": False,
        "eap_types": set(),
        "outer_tls_observed": False,
        "four_way": False,
        "eap_start_seen": False
    })


    type_map = {1: "Identity", 13: "TLS", 21: "TTLS", 25: "PEAP", 26: "MSCHAPv2"}
    tls_types = {13, 21, 25}

    for pkt in packets:

        if not pkt.haslayer(EAPOL):
            continue
        client_mac = getattr(pkt.getlayer(Dot11), "addr2", None) or getattr(pkt, "src", None)
        if not client_mac:
            continue
        info = clients[client_mac]
        info["timestamps"].append(float(pkt.time))  

        eap = pkt.getlayer(EAP)

        if eap:
            if eap.type is None:
                info["eap_start_seen"] = True
            else:
                t = int(eap.type)
                info["eap_types"].add(t)
                info["eap_identity"] = bool(info["eap_identity"] | (t == 1))
                info["outer_tls_observed"] = bool(info["outer_tls_observed"] | (t in tls_types))


        if pkt[EAPOL].type == 3:
            info["four_way"] = True

    return {
        mac: {
            "timestamps": [datetime.fromtimestamp(ts, timezone.utc).isoformat() for ts in v["timestamps"]],
            "eap_identity": v["eap_identity"],
            "eap_types_numeric": sorted(v["eap_types"]),
            "eap_types": [type_map.get(t, str(t)) for t in sorted(v["eap_types"])],
            "outer_tls_observed": v["outer_tls_observed"],
            "four_way_handshake_observed": v["four_way"],
            "eap_start_seen": v["eap_start_seen"]
        }
        for mac, v in clients.items()
    }
    return result