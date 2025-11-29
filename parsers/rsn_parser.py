import struct
from scapy.all import Dot11, Dot11Elt

CIPHER_SUITES = {
    (b"\x00\x0f\xac", 1): "WEP-40",
    (b"\x00\x0f\xac", 2): "TKIP",
    (b"\x00\x0f\xac", 4): "CCMP-128 (AES)",
    (b"\x00\x0f\xac", 5): "WEP-104",
    (b"\x00\x0f\xac", 6): "BIP-CMAC-128",
    (b"\x00\x0f\xac", 9): "GCMP-256",
    (b"\x00\x0f\xac", 12): "BIP-GMAC-256",
}
AKM_SUITES = {
    (b"\x00\x0f\xac", 1): "802.1X (EAP)",
    (b"\x00\x0f\xac", 2): "PSK",
    (b"\x00\x0f\xac", 3): "FT/802.1X",
    (b"\x00\x0f\xac", 4): "FT/PSK",
    (b"\x00\x0f\xac", 8): "SAE (WPA3-Personal)",
    (b"\x00\x0f\xac", 18): "OWE",
}

def parse_suite_selector(data):
    oui, stype = data[:3], data[3]
    return CIPHER_SUITES.get((oui,stype)) or AKM_SUITES.get((oui,stype)) or f"{oui.hex(':')}:{stype}"

def parse_rsn_ie(raw):
    info = {"version": None, "group_cipher": None, "pairwise_ciphers": [], "akm": [], "rsn_capabilities": None}
    offset = 0

    info["version"] = struct.unpack_from("<H",raw,offset)[0]
    offset += 2
 
    info["group_cipher"] = parse_suite_selector(raw[offset:offset+4])
    offset += 4

    pc_count = struct.unpack_from("<H",raw,offset)[0]
    offset += 2
    for _ in range(pc_count):
        info["pairwise_ciphers"].append(parse_suite_selector(raw[offset:offset+4]))
        offset += 4

    akm_count = struct.unpack_from("<H",raw,offset)[0]
    offset += 2
    for _ in range(akm_count):
        info["akm"].append(parse_suite_selector(raw[offset:offset+4]))
        offset += 4

    if offset + 2 <= len(raw):
        rsn_caps = struct.unpack_from("<H",raw,offset)[0]
        info["rsn_capabilities"] = {
            "raw": hex(rsn_caps),
            "MFPC": bool(rsn_caps & (1 << 6)),
            "MFPR": bool(rsn_caps & (1 << 7))
        }

    return info

def rsn_extractor(packets):
    aps = {}

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        dot11 = pkt[Dot11]

        if dot11.type != 0 or dot11.subtype not in (8, 5):
            continue

        bssid = dot11.addr3
        if not bssid:
            continue

        ap = aps.setdefault(bssid, {"BSSID": bssid, "SSID": None, "Channel": None, "RSN": None, "first_seen": float(pkt.time)})

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and ap["SSID"] is None:
                ap["SSID"] = elt.info.decode(errors="ignore") or "<hidden>"
            elif elt.ID == 3 and ap["Channel"] is None:
                ap["Channel"] = elt.info[0]
            elif elt.ID == 48 and ap["RSN"] is None:
                ap["RSN"] = parse_rsn_ie(bytes(elt.info))
            elt = elt.payload.getlayer(Dot11Elt)

    return aps
