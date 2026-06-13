import argparse
import practicaEXTRAOR as nf
from rc1_pcap import pcap_open_offline, pcap_loop, pcap_close


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analizador Netflow simplificado para trazas PCAP"
    )

    parser.add_argument("-i", required=True, help="Nombre del fichero PCAP de entrada")
    parser.add_argument("-T", required=True, type=float, help="Tiempo de expiración de flujos en segundos")

    return parser.parse_args()


def main():
    args = parse_args()

    print("Fichero PCAP:", args.i)

    nf.timeout = args.T
    print("Tiempo de expiracion:", nf.timeout)

    errbuf = bytearray()
    pcap = pcap_open_offline(args.i, errbuf)

    if pcap is None:
        print("Error abriendo el fichero PCAP")
        print(errbuf)
        return

    nf.flows_file = open("flows.txt", "w")

    ret = pcap_loop(pcap, -1, nf.procesa_paquete, None)

    if ret == -1:
        print("Error durante pcap_loop")
    elif ret == -2:
        print("pcap_loop interrumpido")
    else:
        print("Lectura finalizada con exito")

    for flow in nf.flows.values():
        nf.expira_flujo(flow, nf.flows_file)
        nf.flujos_expirados += 1

    nf.flows.clear()

    print("Flujos expirados:", nf.flujos_expirados)
    print("Flujos activos:", len(nf.flows))

    nf.flows_file.close()
    pcap_close(pcap)


if __name__ == "__main__":
    main()