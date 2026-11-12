# Güncelleme Bekçisi (arch-update-guard)

Arch Linux için yerel bir güncelleme panosu. Resmi depo ve AUR güncellemelerini toplar, AUR değişikliklerini kurulmadan önce inceler, Arch haberlerini ve bilinen güvenlik açıklarını gösterir, güncellemeyi senin onayınla bir Konsole penceresinde başlatır.

## Ne yapar

| Bölüm | Kaynak | Not |
|---|---|---|
| Resmi depo güncellemeleri | `checkupdates` (geçici veritabanı, root gerekmez) | Hepsi birlikte güncellenir; Arch kısmi güncellemeyi desteklemez. |
| AUR güncellemeleri | AUR RPC + paket git depoları | Kurulu sürümün commit'i ile yeni commit arasındaki diff incelenir. |
| İnceleme, katman 1 | Sabit kurallar (`aug/rules.py`) | Her zaman çalışır. Yapay zekâ kararı bir kural bulgusunu temizleyemez. |
| İnceleme, katman 2 | Seçtiğin yapay zekâ sağlayıcısı | Hata, zaman aşımı ya da ret durumunda paket "İncelenmedi" sayılır. |
| Arch haberleri | archlinux.org/feeds/news | Son güncellemenden sonra çıkan haberi okuduğunu onaylamadan güncelleme başlamaz. |
| Yeni AUR bağımlılıkları | `.SRCINFO` depends/makedepends farkı | Güncelleme kurulu olmayan bir AUR paketini getiriyorsa o paket de baştan sona incelenir (2 seviyeye kadar). |
| Güvenlik açıkları | security.archlinux.org | Kurulu sürümleri etkileyen kayıtlar; hangi uygulamaları ve çalışan servisleri etkilediği, bekleyen güncellemenin düzeltip düzeltmediği. |
| Yeniden başlatma | pacman.log, systemd, /proc | Eski kütüphaneyle çalışan servisler ve uygulamalar; bilgisayarın yeniden başlatılması gerekip gerekmediği. |
| Ağa açık portlar | `ss`, `docker ps` | Dışarıdan erişilebilen dinleyiciler; Docker'ın tüm ağa açtığı portlar. |
| Sistem | pacman.log, pacdiff, disk | `.pacnew` dosyaları, boş alan. |

AUR paketleri şu kurallarla güncellemeye girer:

- **Temiz ve bekleme süresi dolmuş** paketler otomatik olarak işaretlenir.
- **Bekleme süresindeki** temiz paketleri beklemeden elle onaylayabilirsin.
- **İncelenmemiş, dikkat ya da tehlike** durumundaki paketler yalnızca elle onaylanabilir. Dikkat ve tehlike için paket adını yazman gerekir.
- **Yeni bir AUR bağımlılığı getiren** güncelleme her zaman elle onay ister; bağımlılık temiz olsa bile.
- **Onay commit'e bağlıdır.** Onay, paketin ve getirdiği yeni AUR bağımlılıklarının incelenen commit'lerini kapsar; herhangi biri AUR'da değişirse onay düşer. Güncelleme başlamadan hemen önce ve betik içinde yay çalışmadan önce bu commit'ler yeniden kontrol edilir.

Yeniden başlatma kontrolü hakkında: kullanıcı süreçleri `/proc/*/maps` içinde silinmiş kütüphane aranarak kesin olarak bulunur. root olarak çalışan sistem servislerinin belleği okunamadığı için onlar, başlama zamanı ile ikili dosyalarının ve kütüphanelerinin ait olduğu paketlerin yükseltme zamanı karşılaştırılarak tahmin edilir. Oturumu kapatacak servisler (dbus, logind, sddm…) için servis yerine bilgisayarın yeniden başlatılması önerilir.

## Kullanım

Uygulama menüsünde **Güncelleme Bekçisi** olarak görünür. Komut satırından:

```bash
~/vscode/arch-update-guard/bin/aug open      # panoyu aç
~/vscode/arch-update-guard/bin/aug check     # elle kontrol
~/vscode/arch-update-guard/bin/aug install   # zamanlayıcı + menü kısayolu
~/vscode/arch-update-guard/bin/aug uninstall # ikisini de kaldır
```

Zamanlayıcı (`arch-update-guard-check.timer`) ayarlardaki sıklıkta kontrol yapar ve bir şey varsa KDE bildirimi gösterir. Bildirimdeki "Panoyu aç" düğmesi panoyu açar. Güncellemeyi her zaman sen başlatırsın.

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
| `~/.local/share/arch-update-guard/aur/` | AUR paket depolarının yerel kopyaları (checkout yapılmaz, hiçbir şey çalıştırılmaz) |
| `~/.local/state/arch-update-guard/aug.log` | Günlük |

## Güvenlik notları

- **Sunucu yalnızca 127.0.0.1'de dinler.** Her açılışta rastgele bir erişim anahtarı üretir; anahtar olmadan gelen, `Host` başlığı tutmayan ya da `X-Requested-With: aug` başlığı taşımayan istekleri reddeder. 20 dakika boşta kalınca kapanır.
- **AUR depoları yalnızca okunur.** git sertleştirilmiş ayarlarla (harici diff yok, hook yok, `file://` yok) çağrılır.
- **Güncelleme betiği root olarak çalışmaz.** `sudo` ve tüm pacman/yay soruları açılan terminalde sana sorulur.
- **Yapay zekâ incelemesi bir yardımcıdır, garanti değil.** Upstream kaynağın kendisinin ele geçirilmesini (xz olayı gibi) PKGBUILD diff'inden kimse göremez. O durumda geri dönüş yolun Timeshift anlık görüntüsüdür.
