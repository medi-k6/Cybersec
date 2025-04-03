## on demande à l'utilisateur une adresse ip a ping
import platform
import subprocess

ip = input("Entrez une addresse ip/url ")
#on detecte le system d'exploitation pour adapter la commande
param = "-n" if platform.system().lower() == "windows" else "-c"
#construire la commande ping
command = ["ping", param, "1", ip]
print("Ping en cours...")

#on execute la ping
try:
    result = subprocess.run(command, stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print("cible en ligne")
    else:
        print("Aucune réponse")
except Exception as e:
    print(f"Erreur lors du ping : {e}")
