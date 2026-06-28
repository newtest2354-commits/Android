<div dir="rtl" align="center">

# ⚡ ARISTA MATRIX PIPELINE ⚡

<br>

[![Telegram](https://img.shields.io/badge/Telegram-229ED9?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/aristapanel)
[![YouTube](https://img.shields.io/badge/YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@aristaproject-m3o?si)
[![Element](https://img.shields.io/badge/Element-0DBD8B?style=for-the-badge&logo=element&logoColor=white)](https://matrix.to/#/%23aristaproject:matrix.org)
[![Web Panel](https://img.shields.io/badge/Web_Panel-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://arista-panel.arista-panel.workers.dev/)

<br>
<br>

---

</div>

<div dir="rtl">

## 📌 معرفی پروژه

**ARISTA MATRIX PIPELINE**

یک سیستم پیشرفته و بهینه‌شده برای اسکن، شناسایی و رتبه‌بندی سرورهای Proxy و CDN است. این پروژه با استفاده از معماری Pipeline، به صورت مرحله‌ای IP‌ها را از منابع مختلف جمع‌آوری، پالایش، اسکن و نهایتاً بهترین سرورها را بر اساس معیارهای متعدد رتبه‌بندی می‌کند.

### 🔄 قابلیت استخراج دوطرفه (Bidirectional Extraction)

سیستم **ARISTA** قادر است ارتباط بین **IP** و **دامنه** را در دو جهت شناسایی و استخراج کند:

#### 🔽 استخراج دامنه از IP (IP → Domain)
- **گواهی SSL/TLS**: استخراج دامنه‌های موجود در Common Name (CN) و Subject Alternative Names (SAN) گواهی دیجیتال
- **هدرهای HTTP**: بررسی هدرهایی مانند `Location`، `Host`، `Server` و `Alt-Svc`
- **محتوای HTML**: جستجوی دامنه‌ها در متن صفحات وب (لینک‌ها، منابع و محتوای متنی)
- **Reverse DNS (PTR)**: دریافت نام دامنه از طریق جستجوی معکوس DNS

#### 🔼 استخراج IP از دامنه (Domain → IP)
- **رکوردهای DNS (A)**: دریافت آدرس IPv4 مرتبط با هر دامنه
- **بررسی هم‌زمان**: اسکن چندین دامنه به صورت هم‌زمان برای یافتن IPهای مرتبط
- **یکپارچه‌سازی خودکار**: IPهای استخراج شده به چرخه اسکن اصلی اضافه می‌شوند

> این قابلیت باعث می‌شود تا علاوه بر اسکن IPهای اولیه، شبکه‌های جدیدی از طریق دامنه‌های کشف شده شناسایی و به بانک IP اضافه شوند.

---

## 🚀 امکانات کلیدی

| ویژگی | توضیح |
|-------|-------|
| **پایپلاین چندمرحله‌ای** | اجرای مرحله‌به‌مرحله TCP → TLS → HTTPS → Fingerprint → GEO |
| **اسکن هم‌زمان** | استفاده از ThreadPoolExecutor برای اسکن سریع میلیون‌ها IP |
| **حافظه‌ی کش هوشمند** | ذخیره‌سازی نتایج اسکن برای جلوگیری از اسکن مجدد |
| **شناسایی CDN** | تشخیص خودکار CDN از طریق Headerها، TLS و ASN |
| **جغرافیای IP** | دریافت اطلاعات کشور، شهر و ارائه‌دهنده از چندین منبع |
| **استخراج دوطرفه دامنه و IP** | استخراج دامنه از IP و برعکس از طریق Reverse DNS و رکوردهای A |
| **رتبه‌بندی هوشمند** | امتیازدهی بر اساس TTFB، قابلیت اطمینان، پروتکل و CDN |
| **پشتیبانی از GitHub Actions** | اجرای خودکار و دوره‌ای در GitHub |

---

## 🔄 جریان کاری (Pipeline)

```mermaid
graph LR
    A[دانلود IP] --> B[پالایش IP]
    B --> C[اسکن TCP]
    C --> D[اسکن TLS]
    D --> E[اسکن HTTPS]
    E --> F[شناسایی CDN]
    F --> G[جغرافیا]
    G --> H[استخراج دامنه]
    H --> I[اعتبارسنجی DNS]
    I --> J[رتبه‌بندی نهایی]
```

### شرح مراحل:

#### ۱. دانلود (Downloader)
دانلود لیست IP از منابع مشخص شده در فایل پیکربندی

#### ۲. پالایش (Cleaner)
- حذف IPهای تکراری
- گسترش CIDRها به IPهای مجزا
- نمونه‌گیری از شبکه‌های بزرگ

#### ۳. اسکن TCP
- بررسی باز بودن پورت‌ها
- اندازه‌گیری تأخیر (Latency)
- ذخیره‌سازی نتایج در `tcp_live.txt`

#### ۴. اسکن TLS
- انجام دست دادن TLS با SNIهای مختلف
- دریافت گواهی SSL
- تشخیص ALPN (h2 / http/1.1)

#### ۵. اسکن HTTPS
- ارسال درخواست HTTP/HTTPS
- اندازه‌گیری TTFB
- محاسبه قابلیت اطمینان (Reliability)

#### ۶. شناسایی CDN
- بررسی Headerهای پاسخ
- تحلیل Issuer گواهی
- تشخیص از طریق ASN

#### ۷. جغرافیا (GEO)
دریافت اطلاعات از چندین منبع:
- ip-api.com
- ipwho.is
- ipapi.co
- freeipapi.com
- ipinfo.io
- و چندین منبع دیگر

#### ۸. استخراج دامنه (Domain Extraction)
- **از گواهی SSL** (CN و SAN)
- **از ریدایرکت‌ها** (Location Header)
- **از محتوای HTML** (لینک‌ها و دامنه‌های داخل متن)
- **از PTR** (Reverse DNS برای استخراج دامنه از IP)
- **از رکوردهای A** (استخراج IP از دامنه‌های یافت شده)

#### ۹. اعتبارسنجی DNS
- بررسی وجود رکورد A برای دامنه‌ها
- حذف دامنه‌های نامعتبر

#### ۱۰. رتبه‌بندی نهایی
امتیازدهی بر اساس:
- TTFB (زمان پاسخ)
- قابلیت اطمینان
- پروتکل (h2 امتیاز بیشتر)
- تشخیص CDN معروف
- پورت‌های پایدار (443, 8443, ...)

---

## 🖥️ نصب و اجرا

### نصب وابستگی‌ها

```bash
pip install -r Arista/requirements.txt
```

### اجرای کامل

```bash
python Arista/main.py
```

### اجرای مرحله‌ای

```bash
# اسکن TCP
python Arista/main.py --tcp

# اسکن TLS
python Arista/main.py --tls

# اسکن HTTPS
python Arista/main.py --https

# شناسایی CDN
python Arista/main.py --fp

# دریافت جغرافیا
python Arista/main.py --geo

# نهایی‌سازی و رتبه‌بندی
python Arista/main.py --finalize
```

---

## 📁 خروجی‌ها

| فایل | توضیح |
|------|-------|
| `output/clean_ips.txt` | IPهای پالایش شده |
| `output/tcp_live.txt` | IPهای زنده TCP |
| `output/tls_live.txt` | IPهای دارای TLS |
| `output/https_live.txt` | IPهای پاسخ‌دهنده HTTPS |
| `output/fingerprint_results.txt` | نتایج شناسایی CDN |
| `output/results.txt` | نتایج نهایی با جغرافیا |
| `output/best_ips.txt` | رتبه‌بندی نهایی سرورها |
| `output/domains.txt` | دامنه‌های معتبر استخراج شده |
| `output/domains_ips.txt` | IPهای استخراج شده از دامنه‌ها |
| `output/geo_cache.json` | کش اطلاعات جغرافیایی |
| `output/scanned_cache.txt` | کش IPهای اسکن شده |

### نمونه خروجی `best_ips.txt`:

```
[IP: 1.2.3.4] [PORT: 443] [SCORE=85] [TTFB=120ms] [PROTO=h2] [REL=0.95] [CDN=cloudflare] [TYPE=HTTPS] [DOMAIN=example.com] [SNI=cloudflare.com] [City=Tehran] [Country=Iran] [Provider=MTN]
```

---

## 🔧 GitHub Actions

پروژه از GitHub Actions برای اجرای خودکار و دوره‌ای پشتیبانی می‌کند:

```yaml
on:
  workflow_dispatch:
  schedule:
    - cron: "0 * * * *"  # هر ساعت یک بار
```

### مراحل اجرا در GitHub Actions:

1. **Prepare**: دانلود و پالایش IPها
2. **TCP**: اسکن TCP
3. **TLS**: اسکن TLS
4. **HTTPS**: اسکن HTTPS
5. **Fingerprint**: شناسایی CDN
6. **GEO**: دریافت جغرافیا
7. **Finalize**: رتبه‌بندی نهایی
---

</div>

<div align="center">

## 📡 بانک اطلاعات IPهای برتر

<a href="https://raw.githubusercontent.com/aristapanell-cell/ARISTA-MATRIX-PIPELINE/refs/heads/main/output/best_ips.txt">
  <img src="https://img.shields.io/badge/🚀_مشاهده_لیست_کامل_Best_IPs-00C853?style=for-the-badge" alt="Best IPs">
</a>

<br><br>

✨ **آخرین لیست IPهای رتبه‌بندی‌شده با اطلاعات کامل شامل Score، TTFB، CDN، Protocol، Domain، Country، City و Provider**

</div>

---
<div align="center">

### 📦 **پروژه جمع‌آوری کانفیگ و سابسکریپشن‌ها برای استفاده در کلاینت‌های مختلف**  
**V2rayNG • Hiddify • NekoBox • ClashMeta • SingBox • و سایر کلاینت‌های محبوب**

<br>

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/aristapanell-cell/AriataPanel)

<br>
<br>

<table border="0" cellpadding="20" style="background: linear-gradient(135deg, #1a1a2e, #16213e); border-radius: 20px; border: 2px solid #e94560; margin: 0 auto;">
  <tr>
    <td align="center" style="padding: 25px 40px;">
      <span style="font-size: 1.8em; color: #e94560;">❤️</span>
      <span style="font-size: 1.5em; color: #ffffff; font-weight: bold;"> ساخته شده توسط تیم آریستا </span>
      <span style="font-size: 1.8em; color: #e94560;">❤️</span>
      <br>
      <span style="font-size: 1.2em; color: #ffd700;">🇲‌🇲‌🇩‌</span>
    </td>
  </tr>
</table>

<br>

## ⭐ حمایت

اگر این پروژه برای شما مفید بود، لطفاً با ⭐ در GitHub از ما حمایت کنید.

</div>
