# 🦊 FOX PHISHING SCANNER

**TR / EN — Phishing & Malware URL Security Scanner**

---

## 🇹🇷 TÜRKÇE

### 📌 Proje Hakkında

**FOX PHISHING SCANNER**, bilinen phishing ve malware URL kaynaklarından veri toplayarak URL'lerin erişilebilirlik durumunu kontrol etmek ve tarama sonuçlarını raporlamak için geliştirilmiş Python tabanlı bir güvenlik aracıdır.

Projenin V1 sürümü **PhishTank, URLhaus ve OpenPhish** kaynaklarını kullanır ve URL'leri güvenli bir `HEAD` isteği ile kontrol eder.

V3.1 sürümü ise feed kaynaklarına ek olarak **VirusTotal** ve **Google Safe Browsing** API entegrasyonu sunar.

> ⚠️ Bu proje yalnızca eğitim, savunma, güvenlik araştırması ve farkındalık amaçlıdır.

---

### 🚀 Özellikler

* 🔍 Phishing URL tarama
* 🦠 Malware URL feed desteği
* 📡 PhishTank desteği
* 📡 URLhaus desteği
* 📡 OpenPhish desteği
* 🟢 URL aktiflik kontrolü
* 🔴 VirusTotal API desteği *(V3.1)*
* 🛡️ Google Safe Browsing API desteği *(V3.1)*
* 📊 Rich tabanlı terminal arayüzü
* 📈 İlerleme çubuğu ve tarama istatistikleri
* 🔄 URL tekilleştirme
* ⏱️ Özelleştirilebilir timeout
* 🔢 Maksimum URL sınırı belirleme
* 📄 TXT formatında tarama raporu
* 🔁 Aynı oturum içerisinde yeni tarama başlatabilme

V3.1, VirusTotal sonucunda kötü amaçlı tespitleri ve Google Safe Browsing tehdit eşleşmelerini tarama sonucuna dahil edebilir.

---

### 📂 Dosyalar

```text
FOX PHISHING SCANNER V1.py
FOX PHISHING SCANNER V3.py
README.md
requirements.txt
LICENSE
```

### 🆚 Sürümler

| Özellik                 |  V1 | V3.1 |
| ----------------------- | :-: | :--: |
| PhishTank               |  ✅  |   ✅  |
| URLhaus                 |  ✅  |   ✅  |
| OpenPhish               |  ✅  |   ✅  |
| HEAD kontrolü           |  ✅  |   ✅  |
| TXT raporu              |  ✅  |   ✅  |
| Rich CLI                |  ✅  |   ✅  |
| VirusTotal              |  ❌  |   ✅  |
| Google Safe Browsing    |  ❌  |   ✅  |
| API doğrulama           |  ❌  |   ✅  |
| USOM / BTK referansları |  ❌  |   ✅  |

---

### 🛠️ Gereksinimler

Python 3.x ve aşağıdaki Python paketleri gereklidir:

```text
requests
urllib3
rich
```

Kurulum:

```bash
pip install -r requirements.txt
```

---

### ▶️ Kullanım

V1:

```bash
python "FOX PHISHING SCANNER V1.py"
```

V3.1:

```bash
python "FOX PHISHING SCANNER V3.py"
```

Program çalıştırıldığında interaktif terminal menüsü üzerinden feed seçimi, maksimum URL sayısı, timeout ve çıktı dosyası ayarlanabilir. V3.1'de VirusTotal ve Google Safe Browsing API anahtarları da isteğe bağlı olarak girilebilir.

---

### 🔑 API Anahtarları

V3.1'de aşağıdaki API'ler isteğe bağlıdır:

**VirusTotal**

```text
https://www.virustotal.com/gui/my-apikey
```

**Google Safe Browsing**

```text
https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
```

API anahtarı girilmezse program temel `HEAD` taramasıyla çalışmaya devam eder.

> ⚠️ API anahtarlarınızı kaynak koduna sabitlemeyin veya GitHub'a yüklemeyin.

---

### 📄 Çıktı

Tarama sonunda tarih ve saat bilgisi içeren TXT raporu oluşturulur.

Örnek:

```text
security_scan_20260813_171500.txt
```

V3.1 raporunda URL durumu, kaynak bilgisi, HEAD sonucu ve mevcutsa API sonuçları bulunur.

Örnek:

```text
[AKTIF] [PhishTank (Verified Phishing)] HEAD:200 -> https://example.com
[ZARARLI] [OpenPhish (Phishing Feed)] HEAD:200 | VT:malicious=5 -> https://example.com
[PASIF] [URLhaus (Recent Malware URLs)] HEAD:404 -> https://example.com
```

---

### ⚠️ Sorumluluk Reddi

Bu yazılım yalnızca **eğitim, savunma, güvenlik araştırması ve farkındalık** amacıyla geliştirilmiştir.

Kullanıcı, yazılımı kullanırken yürürlükteki tüm yasalara, servis sağlayıcıların kullanım şartlarına ve ilgili sistemlerin erişim politikalarına uymaktan tamamen sorumludur.

Bu proje; izinsiz erişim, saldırı, kimlik bilgisi hırsızlığı, phishing kampanyası yürütme veya herhangi bir kötü amaçlı faaliyet gerçekleştirme amacıyla kullanılmamalıdır.

Geliştirici, aracın yanlış veya hukuka aykırı kullanımından doğabilecek doğrudan veya dolaylı zararlardan sorumlu değildir.

---

## 🇬🇧 ENGLISH

### 📌 About

**FOX PHISHING SCANNER** is a Python-based security tool designed to collect URLs from known phishing and malware feeds, check their availability, and generate scan reports.

Version 1 uses **PhishTank, URLhaus, and OpenPhish** feeds and performs safe HTTP `HEAD` checks on collected URLs.

Version 3.1 extends the scanner with optional **VirusTotal** and **Google Safe Browsing** API integrations.

> ⚠️ This project is intended only for educational, defensive, security research, and awareness purposes.

---

### 🚀 Features

* 🔍 Phishing URL scanning
* 🦠 Malware URL feed support
* 📡 PhishTank integration
* 📡 URLhaus integration
* 📡 OpenPhish integration
* 🟢 URL availability checking
* 🔴 VirusTotal API support *(V3.1)*
* 🛡️ Google Safe Browsing API support *(V3.1)*
* 📊 Rich terminal interface
* 📈 Progress indicators and statistics
* 🔄 URL deduplication
* ⏱️ Configurable timeout
* 🔢 Maximum URL limit
* 📄 TXT scan reports
* 🔁 Multiple scans in the same session

Version 3.1 can include VirusTotal malicious detections and Google Safe Browsing threat matches in the scan results.

---

### 📂 Files

```text
FOX PHISHING SCANNER V1.py
FOX PHISHING SCANNER V3.py
README.md
requirements.txt
LICENSE
```

### 🆚 Versions

| Feature               |  V1 | V3.1 |
| --------------------- | :-: | :--: |
| PhishTank             |  ✅  |   ✅  |
| URLhaus               |  ✅  |   ✅  |
| OpenPhish             |  ✅  |   ✅  |
| HEAD checking         |  ✅  |   ✅  |
| TXT reports           |  ✅  |   ✅  |
| Rich CLI              |  ✅  |   ✅  |
| VirusTotal            |  ❌  |   ✅  |
| Google Safe Browsing  |  ❌  |   ✅  |
| API verification      |  ❌  |   ✅  |
| USOM / BTK references |  ❌  |   ✅  |

---

### 🛠️ Requirements

Python 3.x and the following packages are required:

```text
requests
urllib3
rich
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

### ▶️ Usage

V1:

```bash
python "FOX PHISHING SCANNER V1.py"
```

V3.1:

```bash
python "FOX PHISHING SCANNER V3.py"
```

The application provides an interactive CLI where users can select feeds, configure the maximum number of URLs, set the timeout, and choose an output filename. V3.1 also allows optional VirusTotal and Google Safe Browsing API keys.

---

### 🔑 API Keys

V3.1 optionally supports:

**VirusTotal**

```text
https://www.virustotal.com/gui/my-apikey
```

**Google Safe Browsing**

```text
https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
```

The scanner can still operate with basic `HEAD` scanning when API keys are not provided.

> ⚠️ Never hard-code API keys into your source code or commit them to GitHub.

---

### 📄 Output

The scanner generates a timestamped TXT report.

Example:

```text
security_scan_20260813_171500.txt
```

Version 3.1 reports include the URL status, source, HEAD result, and available API results.

Example:

```text
[ACTIVE] [PhishTank (Verified Phishing)] HEAD:200 -> https://example.com
[MALICIOUS] [OpenPhish (Phishing Feed)] HEAD:200 | VT:malicious=5 -> https://example.com
[INACTIVE] [URLhaus (Recent Malware URLs)] HEAD:404 -> https://example.com
```

---

### ⚠️ Disclaimer

This software is provided strictly for **educational, defensive, security research, and cybersecurity awareness purposes**.

Users are solely responsible for complying with applicable laws, service terms, and access policies when using this software.

This project must not be used for unauthorized access, attacks, credential theft, phishing campaigns, or other malicious activities.

The developer is not responsible for any direct or indirect damage resulting from misuse or unlawful use of this software.

---

### 🦊 FOX SECURITY

**Developed for defensive security research and cybersecurity awareness.**

**TR:** Güvenlik araştırması ve savunma amaçlı geliştirilmiştir.
**EN:** Developed for defensive security research and cybersecurity awareness.
