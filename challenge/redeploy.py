from pathlib import Path

import dpkt

pcap_file = Path(__file__).parent / "capture.pcap"


def modify_http_requests(input_pcap, output_pcap, new_domain):
    # Open the input PCAP file
    with open(input_pcap, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        all_packets = {}
        modified_packets = {}

        for timestamp, buf in pcap:
            all_packets[timestamp] = buf
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue

            tcp = ip.data

            # Check if the packet contains an HTTP request
            if len(tcp.data) > 0:
                try:
                    http = dpkt.http.Request(tcp.data)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue

                # Modify the Host header
                http.headers["host"] = new_domain

                # Modify the Referer header if it exists
                if "referer" in http.headers:
                    referer = http.headers["referer"]
                    protocol, path = referer.split("//", 1)
                    if "/" in path:
                        _, ref_path = path.split("/", 1)
                        new_referer = f"{protocol}//{new_domain}/{ref_path}"
                    else:
                        new_referer = f"{protocol}//{new_domain}"

                    http.headers["referer"] = new_referer

                # Repack the modified HTTP request into the TCP data
                tcp.data = bytes(http)
                ip.data = tcp

                # Compute checksums
                ip.len = len(ip)
                ip.sum = 0
                ip.sum = dpkt.in_cksum(ip.pack_hdr() + bytes(ip.data))

                # tcp.sum = 0
                # tcp.sum = dpkt.tcp.tcp_cksum(ip, tcp)

                # Repack the IP packet into Ethernet
                eth.data = ip
                modified_packets[timestamp] = bytes(eth)
                # modified_packets.append((timestamp, bytes(eth)))

    # Write the modified packets to a new PCAP file
    with open(output_pcap, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for ts, packet in modified_packets.items():
            writer.writepkt(packet, ts)
        for ts, packet in all_packets.items():
            if ts not in modified_packets:
                writer.writepkt(packet, ts)

    print(f"Modified pcap file saved as {output_pcap}")


# Usage
modify_http_requests(pcap_file, "output.pcap", "newdomain.com")
