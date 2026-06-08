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

    if ethertype == 0x0800:
        user["ipv4"] += 1
    else:
        user["no_ipv4"] += 1

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
        "no_ipv4": 0
    }
    
    ret = pcap_loop(pcap, -1, procesa_paquete, estado)

    if ret == -1:
        print("Error durante pcap_loop")
    elif ret == -2:
        print("pcap_loop interrumpido")
    else:
        print("Lectura finalizada con exito")
    
    print(f"Paquetes leidos: {estado["paquetes"]}")
    print(f"Paquetes IPv4 {estado["ipv4"]}")
    print(f"Paquetes no IPv4: {estado["no_ipv4"]}")
    
    pcap_close(pcap)

if __name__ == "__main__":
    main()
