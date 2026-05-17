<div align="center">

# SSL Certificate Verifier

**Alan adları, IP adresleri, HTTP/HTTPS URL'leri, standart dışı portlar, TLS sürüm tespiti, kök güveni, ara sertifika ve tam zincir doğrulaması için operatör odaklı SSL/TLS sertifika kontrol çalışma alanı.**

![build](https://img.shields.io/badge/build-ready-brightgreen)
![release](https://img.shields.io/badge/release-v0.1.0-blue)
![license](https://img.shields.io/badge/license-MIT-blue)
![runtime](https://img.shields.io/badge/runtime-Go-orange)
![interfaces](https://img.shields.io/badge/interfaces-CLI%20%7C%20GUI-8A2BE2)
![targets](https://img.shields.io/badge/targets-domain%20%7C%20IP%20%7C%20HTTP%20%7C%20HTTPS-0E8A16)
![trust](https://img.shields.io/badge/trust-root%20%7C%20intermediate%20%7C%20chain-yellow)

[Hızlı Başlangıç](#hızlı-başlangıç) • [CLI](#cli-kullanımı) • [GUI](#tarayıcı-gui) • [Hedef Yazımı](#hedef-yazımı) • [TLS Tespiti](#tls-sürüm-tespiti) • [Zincir Doğrulama](#sertifika-zinciri-doğrulaması) • [Özellik Kapsamı](docs/FEATURE_COVERAGE.md) • [Özel Ağlar](#özel-siteler-ve-özel-ca) • [Platformlar](#platform-desteği) • [GitHub/GitLab/Gitea](#github-gitlab-ve-gitea) • [Güvenlik](#güvenlik-modeli) • [Lisans](#lisans)

[English](README.md) • Türkçe

</div>

---

SSL/TLS uç noktalarını kesinti, yayın, taşıma, sertifika yenileme veya uyumluluk incelemesi öncesinde doğrulamak için masaüstü, sunucu ve operasyon ekiplerine uygun bir projedir. Herkese açık internet servislerini, dahili/özel alan adlarını, yalnızca IP ile erişilen cihazları, yük dengeleyicileri, Kubernetes ingress uç noktalarını, ters proxy'leri ve özel portlarda çalışan servisleri kontrol edebilir.

Proje yerel bir CLI ve tarayıcı tabanlı GUI içerir. GUI aynı ikili dosya tarafından sunulur; bu nedenle ağır bir masaüstü framework'ü gerektirmeden Windows, Windows Server, Linux, BSD, Solaris/illumos, macOS ve mobil tarayıcılarda çalışır.

## Neleri kontrol eder

- Alan adları, IP adresleri, `host:port`, `http://` ve `https://` hedefleri.
- Standart veya standart dışı portlardaki HTTPS ve ham TLS servisleri.
- Düz HTTP erişilebilirliği; düz HTTP için sertifika bulunmadığını açıkça belirtir.
- TLS el sıkışma ayrıntıları: anlaşılan TLS sürümü, cipher suite, ALPN ve SNI.
- TLS 1.0, 1.1, 1.2 ve 1.3 sürüm destek probları.
- Zayıf, eski, CBC, AEAD ve forward secrecy sınıflandırmasıyla TLS 1.0-1.2 cipher suite envanteri.
- Leaf sertifika geçerliliği, bitiş tarihi, başlangıç tarihi, SAN'lar, IP SAN'ları ve fingerprint.
- Seri numarası, issuer/subject organizasyonu, doğrulama politikası ipuçları, key usage, EKU, public key hash, SHA-1/SHA-256 fingerprint, OCSP, CRL ve CT/SCT sinyalleri dahil ayrıntılı sertifika meta verileri.
- İşletim sistemi güven deposuyla kök güveni; isteğe bağlı özel PEM CA bundle ile genişletilebilir.
- Ara sertifika varlığı ve zincir kurulabilirliği.
- Hostname veya IP kimliği doğrulaması; IP hedefleri için IP SAN doğrulaması dahil.
- Sertifika yayınlama ve kurulum tanılamasını etkileyen DNS A, AAAA, CNAME, PTR ve CAA kayıtları.
- HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy ve yönlendirme davranışı dahil HTTP/HTTPS response header kontrolleri.
- Yaygın sertifika, protokol, cipher, header ve kurulum problemleri için yerel güvenlik bulguları.
- Otomasyon, CI/CD, GitHub, GitLab, Gitea ve izleme script'leri için JSON çıktı.

## Hızlı başlangıç

```bash
# CLI ve GUI ikili dosyasını derle
go build -o bin/sslcertcheck ./cmd/sslcertcheck

# Herkese açık bir alan adını kontrol et
./bin/sslcertcheck check example.com

# Özel HTTPS portundaki bir servisi kontrol et
./bin/sslcertcheck check https://example.com:8443

# SNI ve hostname doğrulamasıyla dahili IP kontrolü
./bin/sslcertcheck check --servername app.internal.local --verify-name app.internal.local 10.10.0.25:443

# Özel root CA bundle kullan
./bin/sslcertcheck check --ca-file ./corp-root-ca.pem https://portal.internal:9443

# Tarayıcı GUI'sini başlat
./bin/sslcertcheck gui --open --listen 127.0.0.1:8088
```

## CLI kullanımı

```text
sslcertcheck check [flags] <target> [target...]
sslcertcheck gui [flags]
sslcertcheck version
```

Kullanışlı flag'ler:

```text
--format text|json        İnsan tarafından okunabilir metin veya makine tarafından okunabilir JSON çıktı üretir
--port 9443               Ayrıştırılan/varsayılan portu değiştirir
--servername NAME         TLS el sıkışmasında belirli bir SNI adı gönderir
--verify-name NAME        Sertifikayı belirli bir DNS adı veya IP'ye göre doğrular
--timeout 10s             Ağ zaman aşımı
--tls-min 1.2             Ana TLS el sıkışması için minimum TLS sürümü
--tls-max 1.3             Ana TLS el sıkışması için maksimum TLS sürümü
--ca-file FILE            Sistem güven deposuna PEM CA bundle ekler
--no-hostname             Hostname doğrulamasını atlayıp yalnızca zinciri doğrular
--skip-tls-probe          TLS 1.0/1.1/1.2/1.3 sürüm problarını atlar
--include-pem             JSON çıktısına PEM sertifika gövdelerini ekler
--force-tls               Hedef http:// kullansa bile TLS el sıkışması yapar
--skip-dns                DNS A/AAAA/CNAME/CAA/PTR sorgularını atlar
--skip-http               HTTP/HTTPS response header kontrollerini atlar
--skip-cipher-scan        TLS 1.0-1.2 cipher suite envanterini atlar
--fail-on-invalid         TLS doğrulaması başarısızsa çıkış kodu 2 döndürür
```

JSON çıktı örneği:

```bash
sslcertcheck check --format json --fail-on-invalid example.com > report.json
```

## Tarayıcı GUI

GUI aynı ikili dosyaya dahildir ve yerel bir web arayüzü ile küçük bir JSON API sunar.

```bash
sslcertcheck gui --open --listen 127.0.0.1:8088
```

Takım veya laboratuvar kullanımı için özel bir arayüze bind edebilir ve erişimi ağ kontrollerinizle koruyabilirsiniz:

```bash
sslcertcheck gui --listen 10.0.0.15:8088
```

Varsayılan bind adresi `127.0.0.1`'dir. Bu seçim, dahili ağları prob edebilen bir aracı yanlışlıkla dışa açmamak içindir.

## Hedef yazımı

| Girdi | Anlamı |
|---|---|
| `example.com` | 443 portunda HTTPS/TLS kontrolü |
| `example.com:8443` | 8443 portunda HTTPS/TLS kontrolü |
| `192.168.1.10` | IP üzerinde 443 portunda HTTPS/TLS kontrolü |
| `10.0.0.5:9443` | IP üzerinde 9443 portunda HTTPS/TLS kontrolü |
| `https://portal.example.com:9443/path` | URL path bilgisi korunarak HTTPS/TLS kontrolü |
| `http://router.local:8080` | Düz HTTP erişilebilirlik kontrolü; sertifika doğrulaması yoktur |
| `[2001:db8::10]:443` | IPv6 TLS kontrolü |

IP ile erişilen fakat isim tabanlı sertifika sunan uç noktalar için SNI ve doğrulama kimliği verin:

```bash
sslcertcheck check --servername api.internal.example --verify-name api.internal.example 10.0.4.20:443
```

## TLS sürüm tespiti

Checker ana TLS bağlantısını yapar ve devre dışı bırakılmadığı sürece TLS sürümlerini bağımsız olarak dener:

```text
TLS 1.0  destekleniyor / desteklenmiyor
TLS 1.1  destekleniyor / desteklenmiyor
TLS 1.2  destekleniyor / desteklenmiyor
TLS 1.3  destekleniyor / desteklenmiyor
```

Bu kontrol eski protokol maruziyetini tespit etmeye ve modern TLS'in etkin olduğunu doğrulamaya yardımcı olur. Çok yavaş veya rate limit uygulayan uç noktalar için `--skip-tls-probe` kullanın.

`--skip-cipher-scan` ile devre dışı bırakılmadığı sürece checker TLS 1.0, 1.1 ve 1.2 cipher suite'lerini de dener; kabul edilen cipher'ları modern, eski veya zayıf olarak sınıflandırır. Go, TLS 1.3 cipher suite'lerini tek tek zorlamaya izin vermediği için TLS 1.3 cipher bilgisi anlaşılan/problanan TLS bağlantısı üzerinden raporlanır.

## Sertifika zinciri doğrulaması

Doğrulayıcı ana sertifika kontrollerini ayrı ayrı raporlar, böylece operatörler hatayı hızlıca görebilir:

- **Zincir doğrulaması**: Leaf sertifika, sunucunun gönderdiği ara sertifikalar ve seçilen root store ile güvenilir bir köke zincirlenebiliyor mu?
- **Hostname doğrulaması**: Leaf sertifika istenen alan adı, doğrulama adı veya IP SAN ile eşleşiyor mu?
- **Kök güveni**: Zincirin sonundaki root, işletim sistemi güven deposu veya özel CA bundle tarafından güvenilir mi?
- **Ara sertifika tespiti**: Sunucu muhtemel ara sertifikaları eksik mi gönderiyor?
- **Geçerlilik**: Leaf sertifika süresi dolmuş mu veya henüz geçerli değil mi?
- **Self-signed tespiti**: Leaf sertifika kendi kendine imzalı mı?
- **Revocation ve transparency ipuçları**: Sertifika OCSP/CRL endpoint'leri, OCSP Must-Staple veya SCT bilgisi yayımlıyor mu?
- **Kurulum meta verileri**: Issuer, subject, SAN'lar, key usage, EKU, public key boyutu/hash'i ve fingerprint'ler.

TLS el sıkışması, sertifika geçersiz olsa bile peer sertifikalarını toplamaya çalışır ve doğrulamayı ayrıca yapar. Bu sayede bozuk, süresi dolmuş, özel veya eksik zincirler sessizce başarısız olmak yerine incelenebilir.

## Yerel güvenlik bulguları

`security` JSON bölümü ve metin özeti, toplanan kanıtları yerel skor ve grade olarak birleştirir. Bu grade bilerek yerel ve şeffaftır; Qualys SSL Labs'in tescilli grade sistemini veya çoklu vantage point kullanan herkese açık internet tarayıcısını birebir yeniden ürettiğini iddia etmez. Bulgular; süresi dolmuş veya eşleşmeyen sertifikaları, zincir/root trust hatalarını, eski TLS sürümlerini, zayıf veya legacy cipher'ları, eksik HSTS/güvenlik header'larını, eksik CAA kayıtlarını, yerel olarak çıkarılabilen BEAST/ROBOT ön koşullarını ve Heartbleed, Ticketbleed, SSLv3 POODLE gibi düşük seviyeli probları açık `not_tested` bulguları olarak kapsar.

## Özel siteler ve özel CA

Özel siteler, checker'ı çalıştıran makineden erişilebildikleri sürece çalışır. Özel PKI için CA bundle ekleyin:

```bash
sslcertcheck check --ca-file ./company-root-and-intermediates.pem https://intranet.local
```

Özel bundle işletim sistemi güven deposuna eklenir. Sistem root'larının yerine geçmez.

## Platform desteği

| Platform | CLI | GUI | Notlar |
|---|---:|---:|---|
| Windows / Windows Server | Evet | Evet | Yerel `.exe`; GUI varsayılan tarayıcıda açılır |
| Linux | Evet | Evet | Statik derlemeye uygun sunucu/CLI ikili dosyası |
| macOS | Evet | Evet | Yerel ikili dosya; `--open` varsayılan tarayıcıyı kullanır |
| FreeBSD / OpenBSD / NetBSD | Evet | Evet | Tarayıcı GUI'si ikili dosya tarafından sunulur |
| Solaris / illumos | Evet | Evet | Hedef mimari için Go desteğiyle derlenir |
| Android | Evet | Evet | Termux gibi terminal ortamlarıyla CLI; Android tarayıcıyla GUI |
| iOS / iPadOS | Tarayıcı modu | Evet | iOS normalde rastgele yerel CLI ikili dosyalarına izin vermez; erişilebilir bir checker host'undan web GUI kullanın veya Go kütüphanesini imzalı uygulama wrapper'ına gömün |

## Kaynaktan derleme

```bash
# Test
go test ./...

# Mevcut platform için derle
go build -trimpath -ldflags="-s -w" -o dist/sslcertcheck ./cmd/sslcertcheck

# Yaygın hedefler için örnekler
GOOS=windows GOARCH=amd64 go build -o dist/sslcertcheck-windows-amd64.exe ./cmd/sslcertcheck
GOOS=linux   GOARCH=amd64 go build -o dist/sslcertcheck-linux-amd64       ./cmd/sslcertcheck
GOOS=darwin  GOARCH=arm64 go build -o dist/sslcertcheck-darwin-arm64      ./cmd/sslcertcheck
GOOS=freebsd GOARCH=amd64 go build -o dist/sslcertcheck-freebsd-amd64     ./cmd/sslcertcheck
GOOS=android GOARCH=arm64 go build -o dist/sslcertcheck-android-arm64     ./cmd/sslcertcheck
```

Tekrarlanabilir çoklu platform release build'leri için [`scripts/build.sh`](scripts/build.sh) ve [`scripts/build.ps1`](scripts/build.ps1) dosyalarına bakın.

## Docker

```bash
docker build -t sslcertcheck:local .
docker run --rm sslcertcheck:local check example.com
docker run --rm -p 8088:8088 sslcertcheck:local gui --listen 0.0.0.0:8088
```

## GitHub, GitLab ve Gitea

Bu repository platforma hazır dosyalar içerir:

- GitHub Actions için `.github/workflows/ci.yml`.
- GitLab CI için `.gitlab-ci.yml`.
- Gitea Actions için `.gitea/workflows/ci.yml`.
- `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `.gitignore` ve release script'leri.

CLI, `--format json` ile yapılandırılmış çıktı ürettiği ve `--fail-on-invalid` ile bozuk TLS hedefleri için sıfır olmayan çıkış kodu döndürdüğü için CI kullanımına uygundur.

Örnek CI kapısı:

```bash
sslcertcheck check --fail-on-invalid --format json https://production.example.com > tls-report.json
```

## Repository düzeni

```text
cmd/sslcertcheck/        CLI giriş noktası
internal/checker/        TLS, sertifika, zincir ve HTTP kontrol motoru
internal/gui/            Tarayıcı GUI'si ve JSON API
docs/                    Kullanım, platform, release ve güvenlik notları
scripts/                 Platformlar arası build yardımcıları
.github/workflows/      GitHub Actions workflow
.gitea/workflows/       Gitea Actions workflow
.gitlab-ci.yml          GitLab CI workflow
```

## Güvenlik modeli

- Projede telemetry, analytics veya dış callback bulunmaz.
- Checker yalnızca verdiğiniz hedeflere outbound bağlantı açar.
- GUI varsayılan olarak `127.0.0.1` adresine bind eder.
- Özel CA dosyaları checker'ı çalıştıran yerel makineden okunur.
- Sonuçlar dahili hostname'ler, sertifika subject'leri ve fingerprint'ler içerebilir; raporları operasyonel kanıt olarak değerlendirin.

## Lisans

MIT. Ayrıntılar için [`LICENSE`](LICENSE) dosyasına bakın.
