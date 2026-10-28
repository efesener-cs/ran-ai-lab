# Baştan sona container içinde tekrar üretim

Hostta yalnız Docker Engine ve Bash gerekir. Python, ns-3, e2sim, eğitim ve
analiz paketleri image içinde kurulur. Kaynaklar hosttan bağlanmaz; image
checkout'ın kaynak kopyasını içerir. Docker soketi, privileged veya host network
kullanılmaz. Mevcut `flexric` container'ı bu yolun parçası değildir.

İki bağımsız hedef vardır: `native`, mevcut native campaign protokolünün ns-3.38
ortamıdır; `live`, ns-3.42 + FlexRIC E2AP v1/KPM v3 ortamıdır. Container içinde
çalışması native deneyi live-E2 deneyine dönüştürmez. CSV → RRC kontrolü E2 RC
değildir. Bu iki backend'in performans ölçümlerini aynı deney gibi birleştirmeyin.

## Image oluşturma

Temiz checkout'ta, depo kökünden:

```bash
docker build --target native -t ran-ai-lab:native --build-arg BUILD_JOBS=2 .
docker build --target live -t ran-ai-lab:live --build-arg BUILD_JOBS=2 .
bash docker/lab.sh native /tmp/ran-ai-repeat -m unittest discover -p 'test_*.py'
```

Ayrı hostta veya aktif kampanya bittikten sonra uçtan uca kabul testi:

```bash
bash docker/lab.sh native /tmp/ran-ai-acceptance docker/smoke.py --backend native
bash docker/lab.sh live /tmp/ran-ai-acceptance docker/smoke.py --backend live
```

Bu komutlar yeni dizinlerde üç temiz kaynak koşusu, bağımsız model eğitimi,
altı saldırı modu ve analiz çalıştırır; araştırma sonucunun yerini tutmaz.
GitHub Actions `Container acceptance` akışı aynı kontrolleri iki backend için
ayrı job'larda elle tetiklemeyi ve hata loglarını indirmeyi sağlar.

İlk build internet ve C++ derleme süresi gerektirir. Kaynak commit'leri
Dockerfile'da sabittir; değiştirilen build argümanları farklı deney ortamıdır.
Ubuntu paket deposu ve dolaylı Python paketleri tam snapshot değildir. Kesin
ortamı paylaşmak için kullanılan image'ı registry'ye gönderip digest ile saklayın;
`docker image inspect` kimliğini de arşivleyin. Image içindeki
`/opt/dependency-revisions.txt` ve `/opt/python-packages.txt` sürüm dökümüdür.
`RAN_AI_IMAGE=registry/image@sha256:... bash docker/lab.sh ...` aynı image'ı seçer.

Aktif deney sürerken bu build'leri veya entegrasyon denemelerini aynı hostta
başlatmayın. Bu branch'in ilk tesliminde image build ve gerçek simülasyon,
aktif kampanyayı koruma kuralı nedeniyle çalıştırılmamıştır; aşağıdaki kabul
komutlarını kampanya bittikten sonra veya ayrı bir hostta çalıştırın.

## Sıfırdan live veri, eğitim ve eşlenmiş suite

Tüm çağrılarda aynı yeni çıktı dizinini kullanın. `lab.sh`, host kullanıcısıyla
çalışır ve yalnız `results`, `models`, `exports` alt dizinlerini bağlar.
Container içindeki yollar her çağrıda aynı kalır; campaign resume yolları korunur.

```bash
bash docker/lab.sh live /tmp/ran-ai-repeat run_live.py --duration 3 --ues 6 --seed 11 --output results/train-clean
bash docker/lab.sh live /tmp/ran-ai-repeat check_live.py results/train-clean
bash docker/lab.sh live /tmp/ran-ai-repeat run_live.py --duration 3 --ues 6 --seed 23 --output results/validation-clean
bash docker/lab.sh live /tmp/ran-ai-repeat run_live.py --duration 3 --ues 6 --seed 37 --output results/test-clean
bash docker/lab.sh live /tmp/ran-ai-repeat train_ai.py --run-dir results/train-clean --validation-run-dir results/validation-clean --test-run-dir results/test-clean --alpha-grid 0.1 1 10 100 1000 --output ai/artifacts/live
bash docker/lab.sh live /tmp/ran-ai-repeat run_adversarial_suite.py --backend live --model ai/artifacts/live/model.json --duration 3 --ues 6 --seed 41 --epsilon 2 --output results/live-suite41
bash docker/lab.sh live /tmp/ran-ai-repeat analyze_experiments.py results/live-suite41 --output exports/live-analysis
```

Live suite manifesti launcher'ın seçtiği gerçek image kimliğini kaydeder.
Hatalarda da run logları çıktı dizinine kopyalanır. Her run ayrı geçici build
dizini ve RIC loopback adresi kullanır. Yeniden denemede yeni output adı seçin;
mevcut sonuçlar üzerine yazılmaz. Kaynak/model dosyalarını çalışırken değiştirmeyin.

## Native campaign'i container içinde tekrarlama

Native eğitimin başlangıç kontrol modeli için yalnız sentetik fixture kullanılır;
bu model eğitilmiş araştırma modeli veya raporlanacak tahmin başarısı değildir.
Üç saldırısız native kontrol koşusundan bağımsız train/validation/test verisi
üretilir. Kendi protokolünüzde süreyi/UE sayısını ve kaynak seed'lerini sabitleyin.

```bash
bash docker/lab.sh native /tmp/ran-ai-native run_controlled.py --model tests/fixtures/model.json --duration 3 --ues 6 --seed 11 --output results/train-clean
bash docker/lab.sh native /tmp/ran-ai-native run_controlled.py --model tests/fixtures/model.json --duration 3 --ues 6 --seed 23 --output results/validation-clean
bash docker/lab.sh native /tmp/ran-ai-native run_controlled.py --model tests/fixtures/model.json --duration 3 --ues 6 --seed 37 --output results/test-clean
bash docker/lab.sh native /tmp/ran-ai-native train_ai.py --allow-native --run-dir results/train-clean --validation-run-dir results/validation-clean --test-run-dir results/test-clean --alpha-grid 0.1 1 10 100 1000 --output ai/artifacts/native
bash docker/lab.sh native /tmp/ran-ai-native collect_campaign.py --backend native --model ai/artifacts/native/model.json --duration 10 --ues 24 --seeds 41 53 67 --epsilons 0 2 --predictors ridge persistence --robust-budgets-db off 2 --modes none random bias fgsm pgd exact --access two_cell --restarts 5 --plan-only
```

Son komutun yazdırdığı **yeni** campaign yolu ile:

```bash
bash docker/lab.sh native /tmp/ran-ai-native collect_campaign.py --resume results/campaign-YENI_TARIH
```

Campaign analiz ve istatistik aşamalarını da container içinde tamamlar. Tek suite
smoke testi için `run_adversarial_suite.py --backend native` kullanabilirsiniz.
Bu tarif yeni bir tekrar üretimdir; eski kampanyanın ağırlıkları, yerel upstream
değişiklikleri ve ölçüm verileri image içine alınmaz. Eski sonuçlarla bit düzeyinde
eşitlik iddiası yoktur. Bilimsel sözleşmeler için DATASET.md ve EVALUATION.md geçerlidir.
