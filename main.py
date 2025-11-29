#!/usr/bin/env python3
import argparse
from scapy.all import rdpcap, wrpcap
from parsers.rsn_parser import rsn_extractor
from parsers.eap_summarizer import eapol_summarizer
from utils.anonymizer import anonymize_pcap
from utils.io_utils import write_json, write_csv

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Audit Tool (modular version)")
    parser.add_argument("pcap", help="Input PCAP file")
    args = parser.parse_args()

    print(f"Reading pcap {args.pcap}...")
    packets = rdpcap(args.pcap)
    print(f"Loaded {len(packets)} packets.\n")

    print("Select operation(s):")
    print("1. Extract RSN Info")
    print("2. Summarize EAP/EAPOL")
    print("3. Anonymize PCAP")
    choice = input("Enter choices (e.g., 1 2): ").split()

    if "1" in choice:
        aps = rsn_extractor(packets)
        out = input("RSN CSV filename [rsn.csv]: ") or "rsn.csv"
        write_csv(aps, out)

    if "2" in choice:
        eap = eapol_summarizer(packets)
        out = input("EAP summary JSON filename [eap.json]: ") or "eap.json"
        write_json(eap, out)

    if "3" in choice:
        seed = input("Anonymization seed [default-seed]: ") or "default-seed"
        anon_pcap, mapping = anonymize_pcap(packets, seed)
        anon_file = input("Anonymized PCAP filename [anon.pcap]: ") or "anon.pcap"
        map_file = input("Mapping filename [mapping.json]: ") or "mapping.json"
        wrpcap(anon_file, anon_pcap)
        write_json(mapping, map_file)
        print(f"Anonymized PCAP → {anon_file}")
        print(f"Mapping → {map_file}")

    print("\nDone. Exiting Wi-Fi Audit Tool.")

if __name__ == "__main__":
    main()
