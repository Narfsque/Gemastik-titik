# Tulip — setup singkat (analisis trafik + sumber exploit)

Tulip menampilkan flow per service dan bisa **meng-generate cuplikan Python
untuk meniru serangan lawan**. Ini sumber exploit termudah buat tim pemula.

## Sekali, sebelum match (pra-match)
```bash
sudo apt-get install -y docker.io docker-compose
git clone https://github.com/OpenAttackDefenseTools/tulip tools/tulip
cd tools/tulip
sudo docker compose build       # build image (lambat, lakukan pra-match)
```

## Isi daftar service (saat tahu port dari Scoreboard)
Edit `tools/tulip/services/configurations.py`:
```python
vm_ip = "10.13.37.5"            # IP vulnbox KAMU
services = [
    {"ip": vm_ip, "port": 30000, "name": "service1"},
    {"ip": vm_ip, "port": 30010, "name": "service2"},
]
```
Kalau diubah saat match, cukup rebuild service api:
```bash
sudo docker compose up --build -d api
```

## Start Tulip
```bash
sudo docker compose up -d
# buka dashboard di http://localhost:3000  (atau port sesuai .env)
```

## Masukkan trafik (begitu SSH ke service terbuka)
Tulip fork UlisseLab menerima pcap via TCP di port ingest (default 9999):
```bash
# dari folder GEMASTIK/traffic/ :
./capture-and-tulip.sh <your-ip> <ssh-port> 9999
```
`<ssh-port>` = port service + 22 (service :30000 -> SSH :30022).

## Alur "curi exploit"
1. Di dashboard Tulip, filter service yang sedang dibobol; cari flow yang
   menghasilkan flag (ditandai).
2. Klik flow -> Tulip membuat cuplikan Python request-nya.
3. Jadikan exploit farm: salin `exploit_template.py` → `exploit_<svc>.py` di
   `attack_defense/`, tempel cuplikan Tulip ke `exploit()` (ganti IP korban jadi
   parameter `host`), lalu `./farm.py exploit_<svc>.py` → menyasar semua tim.

## Keamanan
Dashboard Tulip memuat flag kamu. Jangan diekspos ke internet — biarkan di
localhost / balik VPN saja.
