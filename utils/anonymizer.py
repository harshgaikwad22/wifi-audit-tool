import hashlib, hmac
from scapy.all import Dot11, EAP, Raw

def mac_pseudonym(mac: str, seed: str):
    if not mac:
        return None
    key = seed.encode()
    hm = hmac.new(key, mac.encode(), hashlib.sha256).digest()
    pseudo = ":".join(f"{b:02x}" for b in hm[:6])
    parts = pseudo.split(":")
    parts[0] = f"{int(parts[0], 16) | 0x02:02x}"
    return ":".join(parts)

def anonymize_pcap(packets, seed: str):
    mapping, anon_packets = {}, []
    for pkt in packets:
        newpkt = pkt.copy()
        if newpkt.haslayer(Dot11):
            dot11 = newpkt[Dot11]
            for field in ("addr1", "addr2", "addr3", "addr4"):
                mac = getattr(dot11, field, None)
                if mac:
                    mapping.setdefault(mac, mac_pseudonym(mac, seed))
                    setattr(dot11, field, mapping[mac])

        if newpkt.haslayer(EAP) and getattr(newpkt[EAP], "type", None) == 1:
            if newpkt.haslayer(Raw):
                newpkt[Raw].load = b"<REDACTED>"
        anon_packets.append(newpkt)
    return anon_packets, mapping
