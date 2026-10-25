# RAN AI Lab

ns-3, FlexRIC ve bir SINR tahmin modeliyle RAN telemetrisine adversarial
müdahaleleri inceleyen araştırma laboratuvarı.

- 4 NR hücresi, LTE anchor/EPC, hareketli UE'ler ve karma TCP/UDP trafik.
- Canlı near-RT RIC, E2 ve KPM izleme hattı.
- Sonraki 100 ms SINR tahmini için residual Ridge modeli.
- Shadow kararları veya atomik CSV → ns-3 RRC API kontrolü.
- Temiz, rastgele bozulma, hedefli FGSM ve PGD için eşlenmiş deneyler.
- CSV veri toplama, doğrulama, PNG/HTML görselleştirme ve PostgreSQL import üretimi.

Bu bir saha kalibrasyonlu digital twin veya üretim 6G sistemi değildir.
Model kapanmış ns-3 trace pencerelerinden beslenir; KPM callback'inden inference
ve E2 RC kontrolü uygulanmaz. Adversarial deneyler modelin gördüğü SINR
telemetrisine sınırlı bias ekler; gerçek RF jamming veya dış hedefe flood yoktur.
Tahmin/sıralama değişimi, gerçek kontrol teyidi ve QoS etkisi ayrı ölçülür.

## Başlangıç

Python 3.10+, NumPy ve analiz için matplotlib gerekir. Simülasyon ayrıca
uyumlu ve önceden derlenmiş ns-3/O-RAN, FlexRIC ve e2sim bağımlılıkları ister.
Bunlar depoda bulunmaz; standart bir Ubuntu container'ı yeterli değildir.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-ai.txt -r requirements-analysis.txt
python3 -m unittest discover -p 'test_*.py'
```

Kaydedilmiş telemetri veya harici ns-3 kaynağı gerektiren testler temiz checkout'ta atlanır.
Diğer testler sentetik girdilerle Docker/veritabanı olmadan çalışır.

Mevcut, hazırlanmış `flexric` container'ıyla ilk temiz veri toplama:

```bash
python3 run_live.py --duration 3 --ues 6
python3 check_live.py --latest
python3 train_ai.py
```

Model yerelde oluşturulduktan sonra eşlenmiş canlı deney:

```bash
python3 run_adversarial_suite.py --backend live --duration 3 --ues 6 --epsilon 2
```

Tam kurulum beklentileri, eğitim, kontrol, campaign ve analiz komutları:
[Çalıştırma kılavuzu](docs/RUNNING.md).

## Belgeler

- [Veri sözlüğü ve veri bölme kuralları](docs/DATASET.md)
- [Kaynak/dependency provenance](docs/PROVENANCE.md)
- [Atıflar ve lisans kapsamı](NOTICE.md)
- [GitHub yayın hazırlığı](docs/GITHUB_PREPARATION.md)
- [Araştırma kaynakları](RESEARCH.md)

`rapor.md`, deney sonuçları, gerçek örnek CSV, eğitilmiş modeller, loglar,
binary'ler ve üretilmiş SQL dosyaları Git dışında tutulur. Yerelde üretilecek
CSV/grafik/rapor yolları komut çıktısında gösterilir; sonuçlar depoyla dağıtılmaz.
Upstream lisansları korunmuştur; yeni kaynaklar için repository çapında lisans
henüz seçilmemiştir. Ayrıntı: [NOTICE.md](NOTICE.md).
