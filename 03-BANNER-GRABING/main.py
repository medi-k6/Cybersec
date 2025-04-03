import socket
import threading


def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout de 1 seconde
            if s.connect_ex((ip, port)) == 0:  # Vérifie si le port est ouvert
                try:
                    s.send(b'HEAD / HTTP/1.1\r\n\r\n')  # Requête HTTP basique pour port 80/443
                    banner = s.recv(1024).decode().strip()
                except:
                    banner = "Bannière non récupérée"

                print(f"[+] Port {port} ouvert – Service détecté : {banner}")
    except Exception as e:
        pass  # Ignore les erreurs


def scan_ports(ip, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=grab_banner, args=(ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    print(f"\n[INFO] Scan de {target_ip} sur les ports {start_port}-{end_port} en cours...\n")
    scan_ports(target_ip, start_port, end_port)