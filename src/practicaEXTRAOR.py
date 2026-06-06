
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
    print("Paquete recibido")

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
    
    ret = pcap_loop(pcap, -1, procesa_paquete, None)

    if ret == -1:
        print("Error durante pcap_loop")
    elif ret == -2:
        print("pcap_loop interrumpido")
    else:
        print("Lectura finalizada con exito")
    
    pcap_close(pcap)

if __name__ == "__main__":
    main()

