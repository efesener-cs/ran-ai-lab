# Çalıştırma kılavuzu

Komutlar depo kökünde çalıştırılır. Sonuçlar ve raporlar yerelde üretilir;
GitHub'dan clone edilen depoda model, binary veya ölçüm verisi bulunmaz.

Tam container kurulumu ve bağımsız veri/eğitim/campaign komutları:
[CONTAINERS.md](CONTAINERS.md). Aşağıdaki host kurulum beklentileri eski native
ve hazırlanmış `flexric` container yolları içindir.

## Bağımlılıklar

- Python 3.10+, `requirements-ai.txt`, `requirements-analysis.txt`.
- Native yol: depoya kardeş `ns-o-ran-ns3-mmwave/build/lib` ve `build/include`,
  g++ ve `/usr/local/include/e2sim` gerektirir. `python3 build_offline.py`
  yerel `ran-ai-offline` binary'sini üretir.
- Live yol: çalışan Docker erişimi, mevcut `flexric` container'ı ve container
  içinde uyumlu, derlenmiş ns-3/O-RAN + FlexRIC + e2sim ağaçları gerektirir.
  Container'ın hazırlanması bu projenin otomatik kurulum kapsamı dışındadır.
- Uyumlu ağaçlar için [PROVENANCE.md](PROVENANCE.md) ve upstream yönergeleri.

Runner kaynakları keşfeder. Gerekirse container yollarını açıkça verin:

```bash
python3 run_live.py --duration 3 --ues 6 \
  --flexric /work/flexric-duranta \
  --ns3 /work/ns-O-RAN-flexric/mmwave-LENA-oran
python3 check_live.py --latest
```

Çıktıda belirtilen koşu klasörünü kaydedin. RIC/E2/KPM kontrolü geçmeden
`train_ai.py` için temiz veri kabul edilmez. RIC portları koşuya özel loopback
adresiyle ayrılır; mevcut ilgisiz süreçler kapatılmaz. Hatalarda loglar da hosta
kopyalanır. Runner kaynak/build cache'lerini yerinde değiştirmez.

## Model eğitimi ve shadow

```bash
python3 train_ai.py --run-dir results/TEMIZ_KOSU
python3 run_live.py --duration 3 --ues 6 \
  --ai-model ai/artifacts/pilot/model.json
python3 check_ai_shadow.py --latest
```

`TEMIZ_KOSU` yerine kendi doğrulanmış, saldırısız koşunuzun dizinini yazın.
`train_ai.py` parametresiz çalışırsa en son E2 doğrulanmış koşuyu seçer;
seçilen koşu saldırılıysa reddeder. Bağımsız test protokolü ayrı run'ları açıkça
verir:

Native koşuları veri kaynağı olarak kabul etmek için açıkça `--allow-native`
verin. Bu, live-E2 doğrulaması değildir; yalnız tamamlanmış, uygun native
kontrol transport'lu koşuyu kabul eder. Validation alpha seçimi yalnız ayrı
validation run'larıyla yapılır; test run'ları seçimde kullanılmaz:

```bash
python3 train_ai.py --allow-native \
  --run-dir results/native-clean-seed41 \
  --validation-run-dir results/native-clean-seed53 \
  --test-run-dir results/native-clean-seed67 \
  --alpha-grid 0.1 1 10 100 1000 \
  --output ai/artifacts/native-seed41-val53-test67
```

Train, validation ve test seed/hash bölmeleri örtüşemez. Alpha, yalnız training
örneklerinde fit edilir; validation MAE seçimi yapar ve final model yine sadece
training örneklerinde seçilmiş alpha ile fit edilir. Test yalnız final raporda
kullanılır. `--validation-run-dir` explicit `--test-run-dir` ister. Validation
vermezseniz `--alpha` kullanılır. Varsayılan aynı koşu içindeki UE bölmesi pilot
içindir; bağımsız koşu/seed değerlendirmesi yerine geçmez. `--allow-native`
varsayılan kapalıdır ve run'ı live-E2 kaynağına dönüştürmez.

## Kontrol ve adversarial evasion

```bash
python3 run_live.py --duration 3 --ues 6 \
  --ai-model ai/artifacts/pilot/model.json --apply-ai-control
python3 check_control.py --latest

python3 run_adversarial_suite.py --backend live --duration 3 --ues 6 \
  --seed 41 --run 1 --epsilon 2 --modes none random bias fgsm pgd exact \
  --access two_cell --predictor ridge --robust-budget-db 1 \
  --output results/suite-seed41-epsilon2
```

Altı mod: none, random, bias, fgsm, pgd, exact. None zorunludur; epsilon 0 ayrı
suite olmalıdır. Erişim `two_cell`, `target_only`, `best_only` olabilir.
`--predictor persistence` mevcut SINR taban çizgisini suite boyunca çalıştırır.
Suite en az 3 ve en fazla 120 UE, en az 3 saniye ister. `--output` suite
klasörünü belirler; koşular altına `<suite-klasör-adı>-none`,
`<suite-klasör-adı>-pgd` gibi yazılır (ör. `results/suite-seed41-epsilon2/`
altında `suite-seed41-epsilon2-pgd`). Manifestte koşu yolları suite köküne
göre çözülür.

Hedef mevcut pencerenin tahmin sıralamasıdır; gelecekteki SINR kullanılmaz.
PGD varsayılan 5 başlangıç ve 10 projeksiyon adımı kullanır, en iyi iteratı
saklar. `--max-step-db` yalnız pencere içindeki bias farkını sınırlar; saldırı
etkisiz olduğunda bias sıfırlanır ve bu global slew limiti değildir. Exact
optimum sabit geçmiş altında tek pencerenin skor marjını çözer.

`--robust-budget-db` bir-adımlı bias aralığında en kötü skor kazancı
histerezisten düşükse handover önerisini durdurur. Model ve diğer özelliklerin
güvenilir olduğunu varsayar; QoS ya da sonraki politika yörüngesine garanti
vermez. Ayrıntı: [EVALUATION.md](EVALUATION.md).

Aktif kontrolde otomatik handover ayarları değişir; kontrolsüz DynamicTtt
koşusuyla doğrudan karşılaştırılmaz. Model çıkarımında simülasyon bariyeri
bekler; batch işleme süresi ölçülür, fakat gerçek near-RT uçtan uca gecikme ölçülmez. Kontrol API isteği ve daha sonraki
CONNECTED_NORMALLY/hedef hücre teyidi ayrı kaydedilir. Bu E2 RC değildir.

Belirli bir koşunun doğrulanması (live olmayan koşuda check_live kullanılmaz):

```bash
python3 check_live.py results/KOSU
python3 check_control.py results/KOSU
python3 check_evasion.py results/KOSU
```

`passed=true` hattın doğru çalıştığıdır; saldırı başarısı veya QoS kaybı değildir.
Ham SINR bias bütçesiyle türetilmiş temporal fark sınırı farklıdır. Audit
zamanı pencere sonundaki karardır; `prior_decision_*` ise uygulama penceresi
başlangıcına eşleşir. Missing audit ile açıkça pasif audit aynı değildir.

## Campaign, CSV ve grafikler

Önce planı üretmek için:

```bash
python3 collect_campaign.py --backend native --duration 10 --ues 24 \
  --seeds 41 53 67 --epsilons 0 2 --predictors ridge persistence \
  --robust-budgets-db off 2 --modes none random bias fgsm pgd exact \
  --access two_cell --restarts 5 --plan-only
```

Çıktıda verilen campaign yoluyla çalıştırın/devam edin:

```bash
python3 collect_campaign.py --resume results/campaign-TARIH
```

Bu örnek 24 suite/144 koşu planlar; simülasyon saati çalışma süresi değildir.
Robust `off` ile `0` ayrı strata'dır: off politika savunmasını kapatır, 0 ise
yalnız sıfır bias aralığında sertifika uygular. Access modu ve predictor da ayrı
strata olarak raporlanır. Tamamlanan suite'ler atlanır; yarım suite yeni
attempt'te seçili modlarıyla tekrarlanır. Eski planlarda `modes` alanı yoksa
resume dört eski modu (none, random, fgsm, pgd) kullanır. Loglar ve başarısız
attempt'ler korunur. Tamamlanınca `analysis/` ve `statistics/` otomatik üretilir.

Mevcut suite'leri ayrıca analiz etmek için:

```bash
python3 analyze_experiments.py results/SUITE --output results/analysis-local
xdg-open results/analysis-local/index.html
python3 summarize_campaign.py results/analysis-local/run_summary.csv \
  --output results/analysis-local/statistics
python3 evaluate_replay.py --model ai/artifacts/native-seed41-val53-test67/model.json \
  --run-dir results/native-clean-seed67 --allow-native --epsilon 2 \
  --access two_cell --robust-budget-db 1 --output results/replay-seed67
```

Birden çok suite argümanı verilebilir. Native/live ve farklı UE/süre
konfigürasyonları ayrı değerlendirilir. Uygulama CSV'si goodput içindir;
radyo CSV'sindeki uygulama değerleri dört hücrede tekrarlanır.
Kampanya özeti clean-paired RX farkı ve seed-cluster bootstrap raporlar; tek
seed için güven aralığı üretmez. AML aynı-window alanları audit penceresini,
`prior_decision_*` uygulama başlangıcındaki kararı gösterir; teyit zamanı tüm
pencere boyunca serving-cell kanıtı değildir. İstatistik için en az iki
bağımsız seed kümesi gerekir; aynı seed içindeki tekrarlar bağımsız örnek sayılmaz.

`evaluate_replay.py` kayıtlı temiz telemetriyi bellekte perturb ederek ridge ve
persistence modellerini altı modda ayrı ayrı inceler. Bölme provenance'ı
varsayılan doğrulanır; yalnız provenance eksik eski modelde açıkça
`--allow-unverified-split` verilebilir. `--allow-native` native kaynaklara izin
verir. Etiket/ground truth temiz ölçülmüş sonraki pencere SINR'ıdır; model girdisi
sentetik olarak değişir, ölçülmüş trafik veya radyo durumu değişmez. Replay,
nedensel QoS/throughput etkisi ya da handover başarısı ölçmez ve ağ kontrolü
uygulamaz. Çıktı `replay_metrics.csv` ve `replay_metrics.json` üretir.
Ayrıntılı alanlar ve sızıntısız train/test bölmesi: [DATASET.md](DATASET.md).

## PostgreSQL ve Grafana

CSV/PNG/HTML üretimi DB gerektirmez. Analiz her koşu için `postgres/*.sql`
import dosyaları hazırlar. Kendi erişebildiğiniz veritabanıyla:

```bash
for file in results/analysis-local/postgres/*.sql; do
  psql -X -v ON_ERROR_STOP=1 -d ran_ai -f "$file" || break
done
```

Aynı run_id farklı CSV hash'iyle tekrar import edilirse işlem durdurulur;
ham ve zenginleştirilmiş importları karıştırmayın. Parola/token Git'e yazılmaz.
Grafana PostgreSQL panel sorguları: `database/grafana_step5.sql`.
Time-series sorgusundaki tarih yalnız görüntüleme ankrajıdır, gerçek yakalama
zamanı değildir. TimescaleDB zorunlu değildir. SQL üretimi, gerçek DB importunun
veya Grafana bağlantısının doğrulanmış olduğu anlamına gelmez.

## Testler ve kaynak üretimi

```bash
python3 -m unittest discover -p 'test_*.py'
python3 scripts/check_publish.py
```

Kaydedilmiş pilot gerektiren testler veri yoksa atlanır. Model/evasion birim
testleri sentetik fixture kullanır. Tam Docker/ns-3 simülasyonu CI'da çalışmaz.
`make_scenario.py` yalnız upstream scenario-zero ağacı mevcutken senaryoyu
tekrar üretmek içindir; normal çalıştırma için depodaki C++ kaynak kullanılır.
