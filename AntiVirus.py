import os
import hashlib
import sys
import requests
import winreg


key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# EnableLUA anahtarı için değeri
value_name = "EnableLUA"

# Değiştirmek istediğiniz değer
new_value = 0

# Registry anahtarı üzerinde işlem yapmak için bağlantıyı açın
with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hkey:
    with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as reg_key:
        winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_DWORD, new_value)

print("EnableLUA değeri başarıyla 0 olarak güncellendi.")


# GitHub reposu URL'si
github_repo_url = "https://raw.githubusercontent.com/swipax/AntiVirus/main/hosts.txt"

# HOSTS dosyasının yolu (Windows'ta)
hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

# GitHub reposundan veriyi al
response = requests.get(github_repo_url)
data = response.text

# HOSTS dosyasına veriyi yaz
with open(hosts_path, "a") as hosts_file:
    hosts_file.write("\n" + data)

print("HOSTS dosyası güncellendi.")

# Şimdi EnableLUA değerini tekrar 1'e çekeceğiz

# Değiştirmek istediğiniz değer
new_value = 1

# Registry anahtarı üzerinde işlem yapmak için bağlantıyı açın
with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hkey:
    # Anahtarı açın veya oluşturun
    with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_WRITE) as reg_key:
        # Değeri ayarlayın
        winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_DWORD, new_value)

print("EnableLUA değeri başarıyla 1 olarak güncellendi.")


# Dosyanın SHA256 karma değerini hesaplamak için bir fonksiyon
def sha256_hash(dosya_yolu):
    sha256 = hashlib.sha256()
    with open(dosya_yolu, "rb") as f:
        while True:
            veri = f.read(65536)  # 64KB'lık parça boyutu
            if not veri:
                break
            sha256.update(veri)
    return sha256.hexdigest()

# Yoksayılacak dizinler
yoksayilan_dizinler = {'AppData', 'Windows', 'ProgramData'}
yoksayilan_dosyalar = {'ntuser.dat.log1', 'ntuser.dat.log2','AMD','NVIDIA Corporation','ntuser.dat','ntuser.dat.LOG2','ntuser.dat.LOG1','swapfile.sys','pagefile.sys','hiberfil.sys','DumpStack.log.tmp'}

# GitHub'dan karma listesini almak için bir fonksiyon
def karma_listesini_al(url):
    try:
        cevap = requests.get(url)
        if cevap.status_code == 200:
            return cevap.text.strip().split('\n')
        else:
            print(f"{url} adresinden karma listesi alınamadı. Durum kodu: {cevap.status_code}")
    except Exception as e:
        print(f"{url} adresinden karma listesi alınamadı: {e}")
    return []

# GitHub'dan karma listesini al
github_karma_url = 'https://github.com/swipax/AntiVirus/blob/main/hashes.txt'
hedef_karma = karma_listesini_al(github_karma_url)

if not hedef_karma:
    print("Karma listesi bulunamadı veya karma listesi alınamadı. Çıkılıyor.")
    sys.exit()

# Dosya bulundu ve silindi mi takip etmek için bir değişken
dosya_silindi = False

# Dizin yolları
kullanici_dizini = "C:/Users"
temel_dizin = "C:/"

# Aranacak dosya uzantısı
arama_uzantilari = {'.exe'}

# C:/Users içindeki dizinler ve dosyalar üzerinde dolaşma
for kok, dizinler, dosyalar in os.walk(kullanici_dizini):
    dizinler[:] = [d for d in dizinler if d not in yoksayilan_dizinler]
    dosyalar[:] = [f for f in dosyalar if f not in yoksayilan_dosyalar]
    for dosya_adi in dosyalar:
        if os.path.splitext(dosya_adi)[1] in arama_uzantilari:
            dosya_yolu = os.path.join(kok, dosya_adi)
            try:
                # Dosyanın SHA256 karma değerini hesapla
                dosya_karmasi = sha256_hash(dosya_yolu)
                if dosya_karmasi in hedef_karma:
                    # Dosyanın karması hedef karmalarla eşleşiyorsa dosyayı sil
                    os.remove(dosya_yolu)
                    print(f"'{dosya_adi}' dosyası başarıyla silindi.")
                    dosya_silindi = True
            except Exception as e:
                print(f"'{dosya_yolu}' dosyası işlenirken hata oluştu: {e}")

# C:/Users içinde dosya silindi mi kontrol et
if dosya_silindi:
    print("'C:/Users' içinde arama tamamlandı.")
    # Dosya_silindi bayrağını sıfırla
    dosya_silindi = False

    # C:/ içindeki dizinler ve dosyalar üzerinde dolaşma
    for kok, dizinler, dosyalar in os.walk(temel_dizin):
        dizinler[:] = [d for d in dizinler if d not in yoksayilan_dizinler]
        dosyalar[:] = [f for f in dosyalar if f not in yoksayilan_dosyalar]
        for dosya_adi in dosyalar:
            if os.path.splitext(dosya_adi)[1] in arama_uzantilari:
                dosya_yolu = os.path.join(kok, dosya_adi)
                try:
                    # Dosyanın SHA256 karma değerini hesapla
                    dosya_karmasi = sha256_hash(dosya_yolu)
                    if dosya_karmasi in hedef_karma:
                        # Dosyanın karması hedef karmalarla eşleşiyorsa dosyayı sil
                        os.remove(dosya_yolu)
                        print(f"'{dosya_adi}' dosyası başarıyla silindi.")
                        dosya_silindi = True
                except Exception as e:
                    print(f"'{dosya_yolu}' dosyası işlenirken hata oluştu: {e}")

if dosya_silindi:
    print("'C:/' içinde arama tamamlandı.")

sys.exit()