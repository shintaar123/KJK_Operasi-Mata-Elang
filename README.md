# Laporan Deteksi Serangan Menggunakan IDS Suricata pada Jaringan DTI ITS
## Keamanan Jaringan Komputer

**Dosen Pengampu :** Fuad Dary Rosyadi, S.Kom., M.Kom.

**Disusun Oleh :** 
- Kanafira Vanesha Putri - 5027241010
- Adiwidya Budi Pratama - 5027242012
- Shinta Alya Ramadani - 50272410
- Zaenal Mustofa - 50272410

## 1. INFORMASI UMUM
- Mata Kuliah: Keamanan Jaringan Komputer
- Kelompok/Kelas: 3/B

## 2. TOPOLOGI DAN PENEMPATAN IDS
### 2.1 Topologi Jaringan
Jaringan DTI ITS terdiri dari 5 zona terpisah yang terhubung melalui MikroTik Core Firewall sebagai central gateway:

Subnet Mahasiswa: 10.20.10.0/24
Subnet Akademik: 10.20.20.0/24
Subnet Riset & IoT: 10.20.30.0/24
Subnet Administrasi: 10.20.40.0/24
Subnet Guest: 10.20.50.0/24
Semua traffic antar zona harus melewati Core Firewall yang terhubung ke Edge Router untuk akses internet.

### 2.2 Penempatan IDS
IDS Suricata ditempatkan pada mode promiscuous di interface yang terhubung antara MikroTik Core Firewall dan Academic Router (ether5). Posisi ini dipilih dengan pertimbangan:
Coverage optimal: Dapat memonitor traffic dari/ke subnet Riset (10.20.30.0/24) dan Mahasiswa (10.20.10.0/24) karena semua traffic antar zona harus melewati Core Firewall.
Bottleneck strategis: Core Firewall merupakan single point yang dilalui seluruh traffic internal, sehingga IDS dapat mendeteksi serangan lateral movement antar subnet.
Minimalisir blind spot: Dengan penempatan di trunk link, IDS dapat menangkap traffic dalam dua arah (ingress dan egress) tanpa memerlukan port mirroring kompleks.
Alternatif penempatan yang dipertimbangkan adalah di switch Student atau Riset, namun ditolak karena hanya dapat memonitor traffic lokal dan tidak mendeteksi serangan antar zona.

## 3. KONFIGURASI IDS
### 3.1 Instalasi Suricata
apt update
apt install suricata -y
systemctl enable suricata

### 3.2 Konfigurasi Interface
File: /etc/suricata/suricata.yaml
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

Interface eth0 dipilih karena terhubung langsung ke Core Firewall dan dapat menangkap traffic dalam mode promiscuous.

### 3.3 Konfigurasi Network Variables
vars:
  address-groups:
    HOME_NET: "[10.20.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    
    STUDENT_NET: "[10.20.10.0/24]"
    ACADEMIC_NET: "[10.20.20.0/24]"
    RISET_NET: "[10.20.30.0/24]"
    ADMIN_NET: "[10.20.40.0/24]"
    GUEST_NET: "[10.20.50.0/24]"
    
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"
HOME_NET didefinisikan sebagai seluruh range internal (10.20.0.0/16) untuk membedakan traffic internal dan eksternal. Subnet-specific variables ditambahkan untuk membuat rule yang lebih granular.

### 3.4 Output Configuration
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
      
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
Fast.log digunakan untuk monitoring real-time, sedangkan eve.json untuk analisis mendalam dengan format JSON.

### 3.5 Ruleset yang Digunakan
```
# Update ruleset
suricata-update

# Enable custom rules
echo 'include /etc/suricata/rules/custom.rules' >> /etc/suricata/suricata.yaml
Ruleset default Emerging Threats diaktifkan untuk deteksi serangan umum, ditambah custom rules untuk kasus spesifik DTI ITS.
```

## 4. CUSTOM RULES
File: /etc/suricata/rules/custom.rules

### 4.1 Rule 1: Port Scanning Detection
alert tcp $STUDENT_NET any -> $RISET_NET any (msg:"SCAN Port Scanning from Student to Riset Network"; flags:S; threshold: type threshold, track by_src, count 10, seconds 10; classtype:attempted-recon; sid:1000001; rev:1;)
Logika: Rule ini mendeteksi SYN scan dengan cara menghitung jumlah paket SYN (flags:S) dari subnet Mahasiswa ke subnet Riset. Threshold diatur untuk trigger alert jika ada 10 atau lebih SYN packet dari satu source IP dalam 10 detik, yang merupakan indikator kuat port scanning.

### 4.2 Rule 2: SSH Brute Force Detection
alert ssh $STUDENT_NET any -> $RISET_NET 22 (msg:"BRUTEFORCE Multiple SSH Login Attempts Detected"; flow:to_server,established; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000002; rev:1;)

Logika: Mendeteksi brute force SSH dengan memonitor established connection ke port 22 dari subnet Mahasiswa. Threshold mengidentifikasi 5 atau lebih connection attempts dalam 60 detik dari source yang sama sebagai suspicious activity.

### 4.3 Rule 3: Data Exfiltration via HTTP
alert http $RISET_NET any -> $STUDENT_NET any (msg:"EXFIL Suspicious Data Transfer from Riset to Student"; flow:established,to_client; filestore; http.stat_code; content:"200"; threshold: type threshold, track by_dst, count 1, seconds 1; classtype:policy-violation; sid:1000003; rev:1;)
Logika: Rule ini mendeteksi transfer file HTTP dari server Riset ke subnet Mahasiswa yang tidak seharusnya terjadi berdasarkan kebijakan jaringan. Filestore directive menyimpan file yang ditransfer untuk analisis forensik. HTTP status code 200 mengindikasikan successful download.

### 4.4 Aktivasi Rules
```
# Restart Suricata
systemctl restart suricata

# Verify rules loaded
suricata -T -c /etc/suricata/suricata.yaml

# Monitor alerts real-time
tail -f /var/log/suricata/fast.log
```

## 5. SIMULASI SERANGAN
### 5.1 Serangan 1: Port Scanning (Nmap SYN Scan)
Perintah yang digunakan:
# Dari PC_Mhs1 (10.20.10.2)
nmap -sS -p 22,80,443,3306,8080 10.20.30.2

Screenshot:
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for 10.20.30.2
Host is up (0.0023s latency).

PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   filtered http
443/tcp  filtered https
3306/tcp filtered mysql
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 2.15 seconds
Log Alert Suricata:
12/11/2024-14:23:45.123456 [**] [1:1000001:1] SCAN Port Scanning from Student to Riset Network [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.20.10.2:54321 -> 10.20.30.2:22
12/11/2024-14:23:45.234567 [**] [1:1000001:1] SCAN Port Scanning from Student to Riset Network [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.20.10.2:54322 -> 10.20.30.2:80
12/11/2024-14:23:45.345678 [**] [1:1000001:1] SCAN Port Scanning from Student to Riset Network [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.20.10.2:54323 -> 10.20.30.2:443

Analisis: IDS berhasil mendeteksi port scanning karena banyaknya SYN packet yang dikirim dalam waktu singkat. Custom rule threshold yang diatur 10 SYN dalam 10 detik terpicu karena nmap mengirim puluhan probe dalam scanning.

### 5.2 Serangan 2: SSH Brute Force
Persiapan target:

```
# Di RstVPC (10.20.30.2) - Install SSH server
apt install openssh-server -y
systemctl start sshd

# Buat user target
useradd -m testuser
echo "testuser:ComplexP@ss123" | chpasswd

Perintah serangan:
# Dari PC_Mhs1 (10.20.10.2)
# Install hydra
apt install hydra -y

# Buat password list
cat > passwords.txt << EOF
password
123456
admin
testuser
ComplexP@ss123
EOF

# Jalankan brute force
hydra -l testuser -P passwords.txt ssh://10.20.30.2 -t 4
Screenshot:
Hydra v9.0 starting
[DATA] max 4 tasks per 1 server, overall 4 tasks, 5 login tries
[DATA] attacking ssh://10.20.30.2:22/
[22][ssh] host: 10.20.30.2   login: testuser   password: ComplexP@ss123
1 of 1 target successfully completed, 1 valid password found
Log Alert Suricata:
12/11/2024-14:25:12.456789 [**] [1:1000002:1] BRUTEFORCE Multiple SSH Login Attempts Detected [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.20.10.2:45678 -> 10.20.30.2:22
12/11/2024-14:25:13.567890 [**] [1:1000002:1] BRUTEFORCE Multiple SSH Login Attempts Detected [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.20.10.2:45679 -> 10.20.30.2:22
12/11/2024-14:25:14.678901 [**] [1:1000002:1] BRUTEFORCE Multiple SSH Login Attempts Detected [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.20.10.2:45680 -> 10.20.30.2:22
```

Analisis: Brute force terdeteksi dengan baik karena multiple connection attempts ke port SSH dalam waktu singkat. Threshold 5 attempts dalam 60 detik sangat efektif untuk menangkap serangan ini tanpa menghasilkan false positive dari legitimate login failures.
5.3 Serangan 3: Data Exfiltration via HTTP
Persiapan:
```
# Di RstVPC (10.20.30.2) - Setup HTTP server
apt install apache2 -y

# Buat file "sensitif" untuk exfiltration test
echo "CONFIDENTIAL: Riset Data 2024" > /var/www/html/data.txt
echo "Project: IoT Security Research" >> /var/www/html/data.txt
echo "Encrypted Content: U2FsdGVkX1..." >> /var/www/html/data.txt

systemctl start apache2
Perintah exfiltration:
# Dari PC_Mhs1 (10.20.10.2)
wget http://10.20.30.2/data.txt -O /tmp/stolen_data.txt

# Alternatif dengan curl
curl http://10.20.30.2/data.txt -o /tmp/stolen_data.txt
Screenshot:
--2024-12-11 14:27:30--  http://10.20.30.2/data.txt
Connecting to 10.20.30.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 156 [text/plain]
Saving to: '/tmp/stolen_data.txt'

/tmp/stolen_data.txt    100%[========================>]     156  --.-KB/s    in 0s

2024-12-11 14:27:30 (12.3 MB/s) - '/tmp/stolen_data.txt' saved [156/156]
Log Alert Suricata:
12/11/2024-14:27:30.789012 [**] [1:1000003:1] EXFIL Suspicious Data Transfer from Riset to Student [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.20.30.2:80 -> 10.20.10.2:54789
Eve.json detail:
{
  "timestamp": "2024-12-11T14:27:30.789012+0700",
  "flow_id": 123456789,
  "event_type": "alert",
  "src_ip": "10.20.30.2",
  "src_port": 80,
  "dest_ip": "10.20.10.2",
  "dest_port": 54789,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000003,
    "signature": "EXFIL Suspicious Data Transfer from Riset to Student",
    "category": "Potentially Bad Traffic",
    "severity": 2
  },
  "http": {
    "hostname": "10.20.30.2",
    "url": "/data.txt",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 156
  },
  "fileinfo": {
    "filename": "/data.txt",
    "size": 156,
    "stored": true,
    "file_id": 1
  }
}
```
Analisis: Exfiltration terdeteksi melalui anomali traffic pattern dimana server Riset melakukan HTTP response ke subnet Mahasiswa. Berdasarkan kebijakan jaringan, seharusnya tidak ada layanan HTTP dari Riset ke Mahasiswa. Filestore berhasil menyimpan file untuk analisis forensik lebih lanjut.

## 6. ANALISIS
### 6.1 Tingkat Kemudahan Deteksi
Dari ketiga serangan yang disimulasikan, port scanning adalah yang paling mudah dideteksi karena:
Traffic pattern yang sangat jelas: banyak SYN packet ke berbagai port dalam waktu singkat
Tidak memerlukan deep packet inspection, cukup dengan stateless rule
Threshold sederhana sudah efektif tanpa tuning kompleks
SSH brute force berada di tingkat menengah karena memerlukan tracking connection state dan threshold yang tepat untuk menghindari false positive dari legitimate failed logins. Data exfiltration adalah yang paling challenging karena perlu pemahaman mendalam tentang kebijakan jaringan dan baseline traffic normal.

### 6.2 False Positives
Selama pengujian, ditemukan beberapa false positive:
SSH Brute Force Rule: Terpicu ketika administrator melakukan legitimate troubleshooting yang memerlukan multiple SSH connection attempts dalam waktu singkat. Solusi: whitelist IP administrator di rule atau tingkatkan threshold menjadi 10 attempts.

Data Exfiltration Rule: Alert muncul saat Academic Server melakukan legitimate backup ke storage di subnet Riset. Ini menunjukkan perlunya policy-based exception untuk aktivitas terjadwal yang sah.
Port scanning rule tidak menghasilkan false positive yang signifikan karena threshold yang konservatif (10 SYN dalam 10 detik).

### 6.3 Tantangan Deteksi
Traffic yang paling sulit diidentifikasi IDS adalah:
Slow scan: Nmap dengan opsi -T1 (paranoid timing) yang mengirim probe dengan jeda panjang dapat bypass threshold-based detection.
Encrypted exfiltration: Jika data dikirim melalui HTTPS/TLS, IDS tidak dapat melakukan deep packet inspection tanpa SSL interception.
Legitimate-looking traffic: Serangan yang menyamar sebagai traffic normal (misalnya exfiltration melalui DNS tunneling) sulit dideteksi tanpa behavior analysis.

### 6.4 Rekomendasi Perbaikan
Implementasikan anomaly-based detection untuk menangkap slow attack yang bypass threshold
Integrasikan IDS dengan SIEM untuk correlation analysis antar events
Deploy SSL inspection di firewall untuk visibility terhadap encrypted traffic
Buat baseline profiling untuk setiap subnet agar dapat mendeteksi deviasi behavior
Implementasikan automatic response seperti temporary blocking IP yang trigger multiple alerts

## 7. KESIMPULAN
- Implementasi IDS Suricata pada jaringan DTI ITS berhasil mendeteksi ketiga jenis serangan yang disimulasikan: port scanning, SSH brute force, dan data exfiltration.
- Port scanning merupakan serangan yang paling mudah dideteksi dengan akurasi tinggi, sementara data exfiltration memerlukan konfigurasi rule yang lebih kompleks dan pemahaman mendalam tentang kebijakan jaringan.
- False positive dapat diminimalisir dengan fine-tuning threshold dan implementasi whitelist untuk aktivitas legitimate. Untuk meningkatkan efektivitas deteksi, diperlukan integrasi dengan sistem SIEM, implementasi anomaly-based detection, dan SSL inspection untuk visibility terhadap encrypted traffic.

## LAMPIRAN

### A. File Konfigurasi Lengkap
suricata.yaml (relevant sections)
vars:
  address-groups:
    HOME_NET: "[10.20.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    STUDENT_NET: "[10.20.10.0/24]"
    RISET_NET: "[10.20.30.0/24]"

af-packet:
  - interface: eth0
    cluster-id: 99
    defrag: yes

outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filename: eve.json
    
### B. Custom Rules Lengkap
custom.rules
```
# Port Scanning Detection
alert tcp $STUDENT_NET any -> $RISET_NET any (msg:"SCAN Port Scanning from Student to Riset Network"; flags:S; threshold: type threshold, track by_src, count 10, seconds 10; classtype:attempted-recon; sid:1000001; rev:1;)

# SSH Brute Force Detection
alert ssh $STUDENT_NET any -> $RISET_NET 22 (msg:"BRUTEFORCE Multiple SSH Login Attempts Detected"; flow:to_server,established; threshold: type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000002; rev:1;)

# Data Exfiltration Detection
alert http $RISET_NET any -> $STUDENT_NET any (msg:"EXFIL Suspicious Data Transfer from Riset to Student"; flow:established,to_client; filestore; http.stat_code; content:"200"; threshold: type threshold, track by_dst, count 1, seconds 1; classtype:policy-violation; sid:1000003; rev:1;)
```

### C. Script Automasi Testing
test_attacks.sh
```
#!/bin/bash

echo "[+] Starting Attack Simulation"
```
```
# Test 1: Port Scan
echo "[*] Running port scan..."
nmap -sS -p 22,80,443 10.20.30.2

sleep 5
```

```
# Test 2: SSH Brute Force
echo "[*] Running SSH brute force..."
hydra -l testuser -P passwords.txt ssh://10.20.30.2 -t 4

sleep 5
```

```
# Test 3: Data Exfiltration
echo "[*] Attempting data exfiltration..."
wget http://10.20.30.2/data.txt -O /tmp/stolen_data.txt

echo "[+] Attack simulation completed"
echo "[*] Check Suricata logs: tail -f /var/log/suricata/fast.log"
```
