import argparse
from rc1_pcap import pcap_open_offline, pcap_loop, pcap_close

def parse_args():
    parser = argparse.ArgumentParser(description="Analizador Netflow simplificado para trazas PCAP")

    parser.add_argument(
        "-i",
        required=True,
        help="Nombre del fichero PCAP de entrada"
    )

    parser.add_argument(
        "-T",
        required=True,
        type=float,
        help="Tiempo de expiración de flujos en segundos"
    )

    return parser.parse_args()

def procesa_paquete(user, pkt_header, pkt_data):
    user["paquetes"] += 1

    if len(pkt_data) < 14:
        return

    ethertype = int.from_bytes(pkt_data[12:14], byteorder="big")

    if ethertype != 0x0800:
        user["no_ipv4"] += 1
        return

    user["ipv4"] += 1

    ip_start = 14

    if len(pkt_data) < ip_start + 20:
        return

    version_ihl = pkt_data[ip_start]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ip_header_len = ihl * 4 # ihl está en palabraas de 32 bits (4 bytes)

    if version != 4:
        return

    if len(pkt_data) < ip_start + ip_header_len:
        return

    protocol = pkt_data[ip_start + 9]

    src_ip = ".".join(str(b) for b in pkt_data[ip_start + 12:ip_start + 16])
    dst_ip = ".".join(str(b) for b in pkt_data[ip_start + 16:ip_start + 20])

    transport_start = ip_start + ip_header_len

    ack = 0

    if protocol == 6:
        if len(pkt_data) < transport_start + 20:
            return

        user["tcp"] += 1
        proto_text = "TCP"

        src_port = int.from_bytes(
            pkt_data[transport_start:transport_start + 2],
            byteorder="big"
        )

        dst_port = int.from_bytes(
            pkt_data[transport_start + 2: transport_start + 4],
            byteorder="big"
        )

        tcp_flags = pkt_data[transport_start + 13]

        if tcp_flags & 0x10:
            ack = 1

    elif protocol == 17:
        if len(pkt_data) < transport_start + 8:
            return

        user["udp"] += 1
        proto_text = "UDP"

        src_port = int.from_bytes(
            pkt_data[transport_start: transport_start + 2],
            byteorder="big"
        )

        dst_port = int.from_bytes(
            pkt_data[transport_start + 2: transport_start + 4],
            byteorder="big"
        )

    else:
        user["otros_ip"] += 1
        return

    timestamp = pkt_header.ts.tv_sec + pkt_header.ts.tv_usec / 1000000

    flow_key = (
        src_ip,
        dst_ip,
        proto_text,
        src_port,
        dst_port
    )

    flows = user["flows"]

    if flow_key not in flows:
        flows[flow_key] = {
            "start_time": timestamp,
            "last_time": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_text,
            "bytes": pkt_header.len,
            "packets": 1,
            "acks": ack
        }
    else:
        flow = flows[flow_key]

        if timestamp - flow["last_time"] > user["timeout"]:
            expira_flujo(flow, user["flows_file"])
            user["flujos_expirados"] += 1

            flows[flow_key] = {
                "start_time": timestamp,
                "last_time": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_text,
                "bytes": pkt_header.len,
                "packets": 1,
                "acks": ack
            }
        
        else:
            flow["last_time"] = timestamp
            flow["packets"] += 1
            flow["bytes"] += pkt_header.len
            flow["acks"] += ack

    print("Flujos activos:", len(flows))

    print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_text})")

def expira_flujo(flow, fichero):
    duracion = flow["last_time"] - flow["start_time"]

    if duracion > 0:
        pps = flow["packets"] / duracion
        kbps = (flow["bytes"] * 8) / duracion / 1000
    else:
        pps = 0
        kbps = 0
    
    linea = (
        f"{flow['start_time']:.6f}\t"
        f"{flow['last_time']:.6f}\t"
        f"{flow['src_ip']}\t"
        f"{flow['dst_ip']}\t"
        f"{flow['src_port']}\t"
        f"{flow['dst_port']}\t"
        f"{flow['protocol']}\t"
        f"{flow['bytes']}\t"
        f"{flow['packets']}\t"
        f"{pps:.3f}\t"
        f"{kbps:.3f}\t"
        f"{flow['acks']}\n"
    )

    fichero.write(linea)

def main():
    args = parse_args()

    print("Fichero PCAP:", args.i)
    print("Tiempo de expiracion:", args.T)

    errbuf = bytearray()
    pcap = pcap_open_offline(args.i, errbuf)

    if pcap is None:
        print("Error abriendo el fichero PCAP")
        print(errbuf)
        return
    
    flows_file = open("flows.txt", "w")

    estado = {
        "paquetes": 0,
        "ipv4": 0,
        "no_ipv4": 0,
        "tcp": 0,
        "udp": 0,
        "otros_ip": 0,
        "flows": {},
        "timeout": args.T,
        "flujos_expirados": 0,
        "flows_file": flows_file
    }

    ret = pcap_loop(pcap, -1, procesa_paquete, estado)

    if ret == -1:
        print("Error durante pcap_loop")
    elif ret == -2:
        print("pcap_loop interrumpido")
    else:
        print("Lectura finalizada con exito")
    
    print(f"Paquetes leidos: {estado['paquetes']}")
    print(f"Paquetes IPv4: {estado["ipv4"]}")
    print(f"Paquetes no IPv4: {estado['no_ipv4']}")
    print(f"Paquetes TCP: {estado['tcp']}")
    print(f"Paquetes UDP: {estado['udp']}")
    print(f"Otros IPv4: {estado['otros_ip']}")

    for flow in estado["flows"].values():
        expira_flujo(flow, estado["flows_file"])
        estado["flujos_expirados"] += 1
    estado["flows"].clear()

    print("Flujos expirados:", estado["flujos_expirados"])
    print("Flujos activos:", len(estado["flows"]))

    flows_file.close()

    pcap_close(pcap)

if __name__ == "__main__":
    main()
