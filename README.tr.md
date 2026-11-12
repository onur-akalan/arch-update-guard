# arch-update-guard (Güncelleme Bekçisi)

**Arch Linux için, AUR güncellemelerini kurulmadan önce inceleyen yerel bir güncelleme panosu.**

[English](README.md)

`yay -Syu`, AUR'un sana verdiği şeyi derler. Haziran 2026'da yüzlerce sahipsiz AUR paketi sahiplenilip PKGBUILD'lerine tek bir zararlı satır (`npm install atomic-lockfile`) eklendi; 2024'teki xz arka kapısı ise yalnızca sürüm arşivinin içindeydi. arch-update-guard güncellemeyle senin arana girer: arka planda her gün kontrol eder, bekleyen her AUR değişikliğini inceler ve yalnızca dikkatini gerektiren bir şey olduğunda haber verir. Güncellemeyi panodan, izlediğin bir terminalde sen başlatırsın.

## Neyi kontrol eder

| | |
|---|---|
| **AUR diff'leri** | Kurulu commit ile yeni commit arasındaki git diff'i (PKGBUILD, `.install`, yamalar) sabit kurallardan ve isteğe bağlı olarak bir yapay zekâ incelemesinden geçer. Yapay zekâ kararı bir kural bulgusunu temizleyemez; yapay zekâ hatası "incelenmedi" sayılır, asla "temiz" değil. |
| **İndirilen kaynaklar** | Tarball, `.deb`, AppImage ve tekil dosyalar indirilir, sağlama toplamı doğrulanır ve **hiçbir şey açılmadan ya da çalıştırılmadan** okunur; kurulu sürümün kaynaklarıyla karşılaştırılır: yeni autostart/systemd/cron/pacman kancası dosyaları, setuid dosyalar, gizli çalıştırılabilirler, kaynak koda eklenen ikililer, değişen derleme betikleri. |
| **xz tarzı saldırılar** | Yüklenmiş sürüm arşivleri upstream git etiketiyle karşılaştırılır; m4/configure/CMake değişiklikleri ile ikili test verisinin birlikte değişmesi işaretlenir; xz arka kapısının hileleri için kurallar vardır (`grep -a`, `tr` takası, bayt kesme, çözüp `eval`'e verme). |
| **Paket ele geçirme** | Sahipsiz paketin sahiplenilmesi, bakımcı değişikliği, ilk kez commit atan kişiler, adı verilen `npm`/`bun`/`pip` kurulumları (`.install` içinde, root olarak: tehlike), yeni AUR bağımlılıkları (onlar da incelenir). |
| **Bilinen olaylar** | Kurulum geçmişin (kaldırılan paketler dahil) Arch'ın yayımladığı ele geçirilmiş AUR paketleri listesiyle karşılaştırılır; kullanıcının yazabildiği PATH dizinlerinde `sudo`/`ssh`/`pacman`'ı gölgeleyen dosyalar aranır. |
| **Arch haberleri** | Son güncellemenden sonra çıkan haberi onaylamadan güncelleme başlamaz. Yapay zekâ her haberi sistemine göre değerlendirir (kurulu paketler, dosyalar, mkinitcpio hook'ları, LUKS, önyükleyici, ekran kartı sürücüsü): seni etkiliyor mu, ne zaman ve hangi komutlarla ne yapmalısın. |
| **Güvenlik açıkları** | Kurulu sürümleri etkileyen security.archlinux.org kayıtları; düzeltme kanıtı (Arch PKGBUILD yamaları, NVD sürüm aralıkları), etkilenen uygulama ve servisler, somut adımlar öneren yapay zekâ değerlendirmesi. |
| **Güncellemeden sonra** | Eski kütüphaneyle çalışan servis ve uygulamalar, yeniden başlatma gereği, `.pacnew` dosyaları, ağa açık portlar. |

Onaylar incelenen commit'e (paketin ve getirdiği her yeni AUR bağımlılığının) bağlıdır ve yay çalışmadan hemen önce yeniden kontrol edilir. Yeni AUR sürümleri, sen daha erken onaylamazsan bir bekleme süresinde (varsayılan 2 gün) bekler.

## Sessiz çalışır

Zamanlanmış kontrol en düşük CPU/disk önceliğinde çalışır, açılıştan sonra 10 dakika bekler ve indirmeleri 3 MB/s ile sınırlar. Sıradan bir gün birkaç saniye sürer ve **bildirim göndermez**. Yalnızca yeni ve önemli bir şey olduğunda haber verir: tehlikeli ya da şüpheli bir AUR güncellemesi, seni etkileyen bir haber, düzeltmesi olmayan kritik bir açık, bilinen bir ele geçirilmiş paket ya da gölgelenmiş bir `sudo`.

## Gereksinimler

`yay` kurulu Arch Linux, Python ≥ 3.14 (Arch'ın varsayılanı), `git`, `pacman-contrib` (`checkupdates`, `pacdiff`), `libsecret` (`secret-tool`, API anahtarları için), `libnotify`, Konsole (güncelleme onun içinde çalışır). İsteğe bağlı: `7zip` (AppImage/rpm listeleme), Chromium (uygulama penceresi), `timeshift-autosnap` (her işlemden önce anlık görüntü).

Yapay zekâ incelemesi isteğe bağlıdır ve sağlayıcı seçilebilir:

- **Claude Code**: kurulu `claude` komutu.
- **Anthropic API**: bir sanal ortamda `pip install -r requirements.txt` gerekir.
- **OpenAI uyumlu herhangi bir uç**: LiteLLM, Ollama, OpenRouter, vLLM…

## Kurulum

```bash
git clone https://github.com/onur-akalan/arch-update-guard.git
cd arch-update-guard
python -m venv .venv && .venv/bin/pip install -r requirements.txt   # isteğe bağlı, Anthropic API için
bin/aug install    # systemd kullanıcı zamanlayıcısı + menü kısayolu
bin/aug open       # panoyu aç
```

Diğer komutlar: `bin/aug check` (şimdi kontrol et), `bin/aug uninstall`. Arayüz Türkçe ve İngilizce kullanılabilir (Ayarlar → Genel → Dil).

## Güvenlik notları

- Pano yalnızca 127.0.0.1'de dinler; her açılışta rastgele bir anahtar, Host denetimi ve CSRF başlığı kullanır; 20 dakika boşta kalınca kapanır.
- AUR depoları sertleştirilmiş git ile okunur (checkout yok, hook yok, harici diff yok, `file://` yok).
- Hiçbir şey root olarak çalışmaz. `sudo` ve tüm pacman/yay soruları izlediğin terminalde sorulur.
- API anahtarları ayarlar dosyasında değil, Secret Service anahtar kasasında tutulur.
- Paketlerden ve haberlerden gelen metin yapay zekâya rastgele işaretli, güvenilmeyen bir blok içinde verilir; içindeki talimatlar kötü niyet belirtisi sayılır.

## Sınırlar

Bu bir ikinci göz, garanti değil. Dikkatli bir saldırgan kodu upstream kaynağın derinlerine, hiçbir diff incelemesinin bulamayacağı yere gizleyebilir; git kaynakları (`-git` paketleri) derleme anında çekildiği için önceden incelenemez; resmi depo paketleri kapsam dışıdır. Geri dönüş yolun olarak anlık görüntüleri (Timeshift) koru.

## Lisans

GPL-3.0-or-later. Bkz. [LICENSE](LICENSE).
