# Çalıştırma kılavuzu

Komutlar depo kökünde çalıştırılır. Sonuçlar ve raporlar yerelde üretilir;
GitHub'dan clone edilen depoda model, binary veya ölçüm verisi bulunmaz.

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
seçilen koşu saldırılıysa reddeder. Ayrı test koşusu için `--test-run-dir`
kullanın. Varsayılan aynı koşu içindeki UE bölmesi yalnız pilot içindir;
bağımsız koşu/seed testinin yerine geçmez. Model kalitesi persistence ile
karşılaştırılır; otomatik iyileşme varsayılmaz.

## Kontrol ve adversarial evasion

```bash
python3 run_live.py --duration 3 --ues 6 \
  --ai-model ai/artifacts/pilot/model.json --apply-ai-control
python3 check_control.py --latest

python3 run_adversarial_suite.py --backend live --duration 3 --ues 6 --epsilon 2
```

Dört koşul: none, random, fgsm, pgd. Aynı seed/run, UE, süre ve saldırı zamanları
kullanılır. `examples/fgsm.json` ölçüm içermeyen bir saldırı girdi örneğidir.
Hedef mevcut temiz tahminde ikinci hücreyi birincinin önüne geçirmektir;
gelecekteki SINR kullanılmaz. FGSM tek analitik gradyan adımı, PGD rastgele
başlangıç ve 10 projeksiyon adımı uygular. Bu modelde sonuçları aynı olabilir.

Aktif kontrolde otomatik handover ayarları değişir; kontrolsüz DynamicTtt
koşusuyla doğrudan karşılaştırılmaz. Model çıkarımında simülasyon bariyeri
bekler; gerçek inference gecikmesi ölçülmez. Kontrol API isteği ve daha sonraki
CONNECTED_NORMALLY/hedef hücre teyidi ayrı kaydedilir. Bu E2 RC değildir.

Belirli bir koşunun doğrulanması (live olmayan koşuda check_live kullanılmaz):

```bash
python3 check_live.py results/KOSU
python3 check_control.py results/KOSU
python3 check_evasion.py results/KOSU
```

`passed=true` hattın doğru çalıştığıdır; saldırı başarısı veya QoS kaybı değildir.
Ham SINR bias bütçesiyle türetilmiş temporal fark sınırı farklıdır; geçmiş
pencerenin etkisi saldırı bitiminden sonra bir pencere sürebilir.

## Campaign, CSV ve grafikler

Önce planı üretmek için:

```bash
python3 collect_campaign.py --backend live --duration 10 --ues 24 \
  --seeds 7 19 --epsilons 0.5 1 2 --plan-only
```

Çıktıda verilen campaign yoluyla çalıştırın/devam edin:

```bash
python3 collect_campaign.py --resume results/campaign-TARIH
```

Bu plan 6 suite/24 koşudur; simülasyon saati çalışma süresi değildir.
Tamamlanan suite'ler atlanır; yarım suite yeni attempt'te dört koşuluyla
tekrarlanır. Loglar ve başarısız attempt'ler korunur. Tamamlanınca analiz
`campaign/analysis/` altında otomatik oluşur.

Mevcut suite'leri ayrıca analiz etmek için:

```bash
python3 analyze_experiments.py results/SUITE --output results/analysis-local
xdg-open results/analysis-local/index.html
```

Birden çok suite argümanı verilebilir. Native/live ve farklı UE/süre
konfigürasyonları ayrı değerlendirilir. Uygulama CSV'si goodput içindir;
radyo CSV'sindeki uygulama değerleri dört hücrede tekrarlanır.
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
