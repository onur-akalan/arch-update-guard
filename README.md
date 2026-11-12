# Güncelleme Bekçisi (arch-update-guard)

Arch Linux için yerel bir güncelleme panosu. Resmi depo ve AUR güncellemelerini toplar, AUR değişikliklerini kurulmadan önce inceler, Arch haberlerini ve bilinen güvenlik açıklarını gösterir, güncellemeyi senin onayınla bir Konsole penceresinde başlatır.

## Ne yapar

| Bölüm | Kaynak | Not |
|---|---|---|
| Resmi depo güncellemeleri | `checkupdates` (geçici veritabanı, root gerekmez) | Hepsi birlikte güncellenir; Arch kısmi güncellemeyi desteklemez. |
| AUR güncellemeleri | AUR RPC + paket git depoları | Kurulu sürümün commit'i ile yeni commit arasındaki diff incelenir. |
| Kaynak dosyalar | AUR güncellemesinin indirdiği tarball, .deb, AppImage, tekil dosyalar | Yeni sürümün kaynakları indirilir, sağlama toplamı doğrulanır ve hiçbir şey çalıştırılmadan içi okunur. Kurulu sürümün kaynaklarıyla karşılaştırılır: eklenen/silinen/değişen dosyalar, otomatik çalışma noktaları (autostart, systemd, cron, pacman kancası, ld.so.preload), setuid dosyalar, gizli çalıştırılabilirler, kaynak koda eklenen derlenmiş ikililer, kurulum ve derleme betiklerinin diff'i. |
| İnceleme, katman 1 | Sabit kurallar (`aug/rules.py`) | Her zaman çalışır. Yapay zekâ kararı bir kural bulgusunu temizleyemez. |
| İnceleme, katman 2 | Seçtiğin yapay zekâ sağlayıcısı | Hata, zaman aşımı ya da ret durumunda paket "İncelenmedi" sayılır. |
| Arch haberleri | archlinux.org/feeds/news | Son güncellemenden sonra çıkan haberi okuduğunu onaylamadan güncelleme başlamaz. Son 60 günün haberleri yapay zekâya değerlendirtilir: bu bilgisayarı etkiliyor mu, ne zaman (güncellemeden önce/sırasında/sonra) ve hangi komutlarla ne yapmalısın. Karar için gerçek durum toplanır: haberde adı geçen paketlerin kurulu ya da bekleyen güncellemede olup olmadığı, adı geçen dosyaların varlığı, initramfs hook'ları, LUKS, önyükleyici, ekran kartı sürücüsü. Seni etkilemeyen haber bildirim göndermez; etkileyen haber bildirimde ne zaman yapılacağını söyler. |
| Yeni AUR bağımlılıkları | `.SRCINFO` depends/makedepends farkı | Güncelleme kurulu olmayan bir AUR paketini getiriyorsa o paket de baştan sona incelenir (2 seviyeye kadar). |
| Güvenlik açıkları | security.archlinux.org | Kurulu sürümleri etkileyen kayıtlar; hangi uygulamaları ve çalışan servisleri etkilediği, bekleyen güncellemenin düzeltip düzeltmediği. |
| Düzeltme kanıtı | Arch PKGBUILD, NVD, CVE açıklaması | Sırasıyla: Arch paketi CVE adıyla yama uyguluyor mu; NVD sürüm aralığı; açıklamadaki "X'ten önceki sürümler". Kanıt "düzeltilmiş" diyorsa kayıt ayrı grupta gösterilir. |
| Yapay zekâ değerlendirmesi | Seçili sağlayıcı | Kurulu sürüm etkileniyor mu, bu makine için gerçek risk ne, ne yapmalısın. Puan düşük olsa bile etkileniyorsan somut adım önerir. Etkin açıklar her kontrolde, diğerleri istenince değerlendirilir. |
| Bilinen saldırılar | Arch'ın yayımladığı ele geçirilmiş AUR paketleri listesi (Haziran 2026 "Atomic Arch"), pacman.log, PATH | Listedeki bir paket saldırı tarihinden sonra bu bilgisayarda kurulduysa (sonradan kaldırılmış olsa bile) kritik uyarı verir. `sudo`, `ssh`, `pacman` gibi komutları gölgeleyen dosyaları (`~/.local/bin/sudo` gibi) ve kabuk dosyalarındaki sarmalayıcıları arar. Liste `security.compromised_lists` ayarına yenileri eklenebilir. |
| Yeniden başlatma | pacman.log, systemd, /proc | Eski kütüphaneyle çalışan servisler ve uygulamalar; bilgisayarın yeniden başlatılması gerekip gerekmediği. |
| Ağa açık portlar | `ss`, `docker ps` | Dışarıdan erişilebilen dinleyiciler; Docker'ın tüm ağa açtığı portlar. |
| Sistem | pacman.log, pacdiff, disk | `.pacnew` dosyaları, boş alan. |

AUR paketleri şu kurallarla güncellemeye girer:

- **Temiz ve bekleme süresi dolmuş** paketler otomatik olarak işaretlenir.
- **Bekleme süresindeki** temiz paketleri beklemeden elle onaylayabilirsin.
- **İncelenmemiş, dikkat ya da tehlike** durumundaki paketler yalnızca elle onaylanabilir. Dikkat ve tehlike için paket adını yazman gerekir.
- **Yeni bir AUR bağımlılığı getiren** güncelleme her zaman elle onay ister; bağımlılık temiz olsa bile.
- **Sahiplenme ve bakımcı değişikliği uyarı verir.** Sahipsiz bir paketin biri tarafından sahiplenilmesi (Haziran 2026 saldırısının yöntemi) ve bakımcı değişikliği elle onay ister. PKGBUILD ya da `.install` içinde adı verilen bir npm/bun/pip paketinin indirilmesi (`npm install atomic-lockfile` gibi) uyarı verir; `.install` betiğinde (root olarak) tehlike sayılır.
- **Onay commit'e bağlıdır.** Onay, paketin ve getirdiği yeni AUR bağımlılıklarının incelenen commit'lerini kapsar; herhangi biri AUR'da değişirse onay düşer. Güncelleme başlamadan hemen önce ve betik içinde yay çalışmadan önce bu commit'ler yeniden kontrol edilir.

Kaynak inceleme hakkında:

- **Hiçbir şey çalıştırılmaz ya da diske açılmaz.** tar, zip ve .deb Python'un standart kütüphanesiyle bellekte okunur. AppImage, rpm ve iso yalnızca `7z` ile listelenir ve seçili dosyalar `7z x -so` ile okunur. Bu biçimlerde dosyalar yalnızca boyutla karşılaştırılabilir.
- **Karşılaştırma tabanı:** her incelemenin özeti commit'e bağlı olarak saklanır (`~/.local/share/arch-update-guard/sources/`). Güncellemeden sonra kurulu sürümün özeti bir sonraki güncellemenin tabanı olur. Bir paket ilk kez incelenirken kurulu sürümün kaynakları da bir kez indirilir (Ayarlar'dan kapatılabilir).
- **İndirme süresi sınırlıdır.** Süre dolunca indirme bir sonraki kontrolde kaldığı yerden devam eder; inceleme bitene kadar paket otomatik seçilmez ve yapay zekâ incelemesi bekletilir.
- **Aynı dosya iki kez inmez.** Sağlama toplamı doğrulanan dosyalar `~/.cache/arch-update-guard/sources/` altında saklanır; güncelleme betiği bunları yay'ın derleme klasörüne kopyalar. makepkg sağlama toplamını yine kendisi doğrular. Paket kurulduktan sonraki kontrolde bu kopyalar silinir.
- **xz tarzı saldırılara karşı üç ek kontrol:**
  - *Derleme sistemi dosyaları:* `*.m4`, `configure.ac`, `Makefile.am`, CMake ve meson dosyaları hangi klasörde olursa olsun önemli sayılır; değişiklikleri kurallardan geçer ve yapay zekâya gider. Elle yazılan dosyaların küçük diff'leri, yeniden üretilen `configure`/`Makefile.in` dosyalarından önce gösterilir. xz arka kapısının kalıpları için kurallar vardır: `grep -a` ile ikili dosyada arama, `tr` ile boşluk/sekme takası, `head -c`/`dd` ile bayt kesme, çözülen verinin `eval` ya da `sh`'ye verilmesi.
  - *Test verisi + derleme betiği:* aynı sürümde hem ikili test/veri dosyaları hem de m4, `configure.ac`, CMake gibi derleme dosyaları değişirse uyarılır. Derleme dosyaları git etiketindekiyle aynıysa uyarı bilgi düzeyine iner.
  - *Sürüm arşivi ↔ git etiketi:* bakımcının yüklediği arşivler (ör. GitHub "releases/download") aynı sürümün git etiketinden üretilen arşivle karşılaştırılır. Git'tekinden farklı dosyalar ve yalnızca arşivde olan beklenmedik dosyalar uyarı verir. Autotools/gettext çıktısı (`configure`, `Makefile.in`, `build-aux/`, `m4/` kopyaları) yalnızca arşivde bulunabilir; bunlar ayrı listelenir ama içerikleri yine taranır. Depo GitHub, GitLab ya da Codeberg'de olmalı; etiket, `pkgver`'den türetilen adlarla aranır. Hazır ikili paketlerde (`-bin`, .deb, AppImage) bu adım atlanır.
  - Gerçek xz 5.8.1 arşivine arka kapının satırları ve bir ikili test dosyası enjekte edilerek denendi: kurallar, yapısal uyarı, git karşılaştırması ve yapay zekâ dördü de yakaladı. Temiz 5.8.1 arşivinde yalnızca bilgi satırı çıktı.
- **Sınırlar:** git/svn kaynakları derleme anında çekildiği için önceden incelenemez. Sağlama toplamı `SKIP` olan dosyalar incelemeden sonra sunucuda değişebilir. Bir .deb'in kendi kurulum betikleri (postinst) makepkg tarafından çalıştırılmaz; yine de gösterilir. Kaynakların tamamı değil, güvenlik açısından önemli dosyaları ve değişiklik listesi incelenir; xz olayındaki gibi derinlere gizlenmiş bir arka kapıyı bu yöntem garanti yakalamaz.

Yeniden başlatma kontrolü hakkında: kullanıcı süreçleri `/proc/*/maps` içinde silinmiş kütüphane aranarak kesin olarak bulunur. root olarak çalışan sistem servislerinin belleği okunamadığı için onlar, başlama zamanı ile ikili dosyalarının ve kütüphanelerinin ait olduğu paketlerin yükseltme zamanı karşılaştırılarak tahmin edilir. Oturumu kapatacak servisler (dbus, logind, sddm…) için servis yerine bilgisayarın yeniden başlatılması önerilir.

## Kullanım

Uygulama menüsünde **Güncelleme Bekçisi** olarak görünür. Komut satırından:

```bash
~/vscode/arch-update-guard/bin/aug open      # panoyu aç
~/vscode/arch-update-guard/bin/aug check     # elle kontrol
~/vscode/arch-update-guard/bin/aug install   # zamanlayıcı + menü kısayolu
~/vscode/arch-update-guard/bin/aug uninstall # ikisini de kaldır
```

Zamanlayıcı (`arch-update-guard-check.timer`) ayarlardaki sıklıkta kontrol yapar. Güncellemeyi her zaman sen başlatırsın.

**Arka planda fark edilmemesi için:**

- Kontrol en düşük öncelikte çalışır (`Nice=19`, CPU ve disk için `idle` sınıfı, `MemoryHigh=1500M`): yalnızca başka bir işin kullanmadığı CPU ve disk zamanını alır.
- Bilgisayar açıldıktan sonra 10 dakika bekler (ayarlanabilir), böylece oturum açılışını yavaşlatmaz.
- Kaynak indirmeleri zamanlanmış kontrolde 3 MB/s ile sınırlıdır (ayarlanabilir); elle başlatılan kontrolde sınır yoktur.
- Sıradan bir gün (yeni AUR sürümü yok ya da kaynaklar zaten incelenmiş) yaklaşık 10-60 saniye ve birkaç saniye CPU sürer. Uzun süren tek iş, yeni bir AUR sürümünün kaynaklarının ilk kez indirilmesidir.

**Bildirimler** varsayılan olarak yalnızca yeni ve önemli bir şey olduğunda gelir: tehlikeli ya da uyarılı bir AUR güncellemesi, okunmamış bir Arch haberi, düzeltmesi olmayan kritik/yüksek bir açık ya da bekleyen güncellemeyle kapanan bir açık. Her olay bir kez bildirilir. Sıradan güncellemeler sessizce panoda bekler; 14 günden uzun süre güncelleme yapılmazsa haftada bir hatırlatma gelir. Bildirimdeki "Panoyu aç" düğmesi panoyu açar.

## Yapay zekâ sağlayıcıları

Ayarlar → Sağlayıcılar bölümünden istediğin kadar sağlayıcı ekleyip birini etkin seçebilirsin. Her paket kartından farklı bir sağlayıcıyla yeniden inceletmek de mümkün.

| Tür | Ne için | Ayar |
|---|---|---|
| Claude Code | Kurulu `claude` komutu, abonelik kotası | Model: `sonnet`, `opus`, `haiku` |
| Anthropic API | API anahtarı (örneğin hediye krediler) | Model (varsayılan `claude-opus-5-5`), effort, isteğe bağlı adres |
| OpenAI uyumlu | LiteLLM, Ollama, OpenRouter, vLLM… | Adres (`http://…/v1`), model, JSON kipi |

API anahtarları `settings.json` dosyasına değil, masaüstünün anahtar kasasına (Secret Service, `secret-tool`) yazılır.

Anthropic API ile Opus 5.5, Sonnet 5.5 ve Fable modellerinde server-side fallback açıktır: güvenlik sınıflandırıcısı incelemeyi reddederse istek aynı çağrı içinde başka bir modelle yeniden denenir. Zincirin tamamı reddederse paket "İncelenmedi" olur.

Yerel modeller katı JSON şemasını desteklemiyorsa JSON kipini `json_object` ya da `yok` yap.

## Dosyalar

| Yol | İçerik |
|---|---|
| `~/.config/arch-update-guard/settings.json` | Ayarlar (anahtar içermez) |
| `~/.local/share/arch-update-guard/report.json` | Son kontrolün raporu |
| `~/.local/share/arch-update-guard/state.json` | Onaylar, inceleme önbelleği, bakımcı geçmişi, okunan haberler |
| `~/.local/share/arch-update-guard/sources/` | Kaynak dosya özetleri (dosya listesi, özetler, önemli metin dosyaları), commit başına |
| `~/.cache/arch-update-guard/sources/` | İncelenmiş ve doğrulanmış kaynak dosyalar; güncellemede yay'a verilir |
| `~/.local/share/arch-update-guard/aur/` | AUR paket depolarının yerel kopyaları (checkout yapılmaz, hiçbir şey çalıştırılmaz) |
| `~/.local/state/arch-update-guard/aug.log` | Günlük |

## Güvenlik notları

- **Sunucu yalnızca 127.0.0.1'de dinler.** Her açılışta rastgele bir erişim anahtarı üretir; anahtar olmadan gelen, `Host` başlığı tutmayan ya da `X-Requested-With: aug` başlığı taşımayan istekleri reddeder. 20 dakika boşta kalınca kapanır.
- **AUR depoları yalnızca okunur.** git sertleştirilmiş ayarlarla (harici diff yok, hook yok, `file://` yok) çağrılır.
- **Güncelleme betiği root olarak çalışmaz.** `sudo` ve tüm pacman/yay soruları açılan terminalde sana sorulur.
- **Yapay zekâ incelemesi bir yardımcıdır, garanti değil.** Kaynak inceleme, arşive eklenen kalıcılık dosyalarını, betik değişikliklerini ve beklenmedik ikilileri gösterir; ama upstream kodun derinlerine ustaca gizlenmiş bir arka kapıyı (xz olayı gibi) yakalayacağının garantisi yoktur. O durumda geri dönüş yolun Timeshift anlık görüntüsüdür.
