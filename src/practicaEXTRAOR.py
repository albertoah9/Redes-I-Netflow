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

    print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_text})")

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
    
    estado = {
        "paquetes": 0,
        "ipv4": 0,
        "no_ipv4": 0,
        "tcp": 0,
        "udp": 0,
        "otros_ip": 0
    }
    
    ret = pcap_loop(pcap, -1, procesa_paquete, estado)

    if ret == -1:
        print("Error durante pcap_loop")
    elif ret == -2:
        print("pcap_loop interrumpido")
    else:
        print("Lectura finalizada con exito")
    
    print(f"Paquetes leidos: {estado["paquetes"]}")
    print(f"Paquetes IPv4: {estado["ipv4"]}")
    print(f"Paquetes no IPv4: {estado["no_ipv4"]}")
    print(f"Paquetes TCP: {estado["tcp"]}")
    print(f"Paquetes UDP: {estado["udp"]}")
    print(f"Otros IPv4: {estado["otros_ip"]}")
    
    pcap_close(pcap)

if __name__ == "__main__":
    main()
