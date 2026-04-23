#!/usr/bin/env python3
import socket
import time
import random
from datetime import datetime

# Konfigurasi
SYSLOG_SERVER = "localhost"
SYSLOG_PORT = 514
ATTACKER_IP = "185.220.101.{}".format(random.randint(1, 255)) # IP acak biar kelihatan nyata
TARGET_USER = "root"

def generate_syslog(failed_count):
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()
    
    # Format log Syslog standar SSH failed login
    log_message = f"{timestamp} {hostname} sshd[{random.randint(1000, 9999)}]: Failed password for {TARGET_USER} from {ATTACKER_IP} port {random.randint(40000, 60000)} ssh2"
    
    # Format paket UDP Syslog (PRI + TAG + MSG)
    # PRI 13 = Facility 1 (User) + Severity 5 (Notice)
    packet = f"<13>{log_message}"
    return packet.encode('utf-8')

print(f"🚀 Memulai simulasi Brute Force Attack dari IP: {ATTACKER_IP}")
print(f"🎯 Target: User '{TARGET_USER}'")
print(f"📡 Mengirim log ke {SYSLOG_SERVER}:{SYSLOG_PORT}...\n")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    for i in range(1, 11): # Kirim 10x percobaan gagal
        data = generate_syslog(i)
        sock.sendto(data, (SYSLOG_SERVER, SYSLOG_PORT))
        print(f"[{i}/10] Sent: Failed password for {TARGET_USER} from {ATTACKER_IP}")
        time.sleep(0.5) # Jeda setengah detik biar realtime
    
    print("\n✅ Simulasi selesai! Cek dashboard Grafana atau log processor.")
    print("💡 Jika rule 'SSH Brute Force' aktif, alert seharusnya muncul dalam < 5 detik.")

except Exception as e:
    print(f"❌ Error mengirim log: {e}")
    print("Pastikan container 'siem-processor' sudah jalan dan port 514 UDP terbuka.")

finally:
    sock.close()
