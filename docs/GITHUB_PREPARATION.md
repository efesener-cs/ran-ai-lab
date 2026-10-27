# GitHub yayın hazırlığı

Bu depo yalnız kaynak, test, çalışma yönergeleri, girdi örneği ve atıfları içerir.
`reports/rapor.md`, `results/`, ölçüm örnek CSV'si, yerel deney notları, modeller,
loglar, build ürünleri ve üretilmiş import dosyaları `.gitignore` ile dışlanır.
Gerçek deney sonuçları yayınlanmaz. `tests/fixtures/model.json` elle yazılmış
sentetik birim test girdisidir; eğitilmiş model değildir.

## Yerel kontrol

```bash
python3 -m unittest discover -p 'test_*.py'
python3 scripts/check_publish.py
git diff --cached --check
git diff --cached --stat
git status --short --ignored
```

`check_publish.py`, index'e zorla eklenmiş rapor/sonuçları da reddeder.
CI aynı kontrolü ve Docker/DB gerektirmeyen testleri çalıştırır. Kaydedilmiş
telemetri testleri temiz checkout'ta atlanır; simülasyon CI'da doğrulanmaz.

Yeni değişiklikleri hazırlamak için `git add .` kullanılabilir; ignore ve
publication kontrolü birlikte korunmalıdır. `git add -f` ile sonuçları dahil
etmeyin. Git ignore daha önce commit edilmiş dosyaları silmez; yayın öncesi
index kontrolü bu yüzden ayrıca yapılır.

## Commit ve push

Git deposu `main` dalında yerelde hazırlanmıştır. Otomatik commit, remote
oluşturma veya push yapılmaz. Kullanıcı kendi kimliği/hedef deposuyla:

```bash
git commit -m "Prepare RAN AI simulation source and reproducible workflows"
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

`OWNER/REPOSITORY` yer tutucudur. Remote zaten varsa önce `git remote -v`
ile inceleyin; var olan hedefi otomatik değiştirmeyin. GitHub'da boş depo
oluşturun; ek README/commit ile bağımsız geçmiş üretmeyin. Kimlik/token
kaynak dosyalarına veya komutlara gömülmez.

## Lisans ve provenance

[NOTICE.md](../NOTICE.md) ve [PROVENANCE.md](PROVENANCE.md) upstream atıflarını
ve lisans kapsamını açıklar. GPL-2.0 senaryo başlığı korunur; FlexRIC ayrı
CSSL bağımlılığıdır. Yeni kaynaklara repository çapında lisans seçilmemiştir;
MIT/Apache lisansı varmış gibi sunulmaz. Lisanslı bir release duyurulmadan önce
hak sahibinin lisans seçimi tamamlanmalıdır. Rapor ve veri için release/upload
hazırlanmaz; bunlar kullanıcının talebiyle yerelde kalır.
