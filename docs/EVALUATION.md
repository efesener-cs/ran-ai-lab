# Değerlendirme protokolü

Bu depo, sentetik ns-3 koşularında telemetri bias'ının model skorları, kararlar ve
uygulama trafiğiyle ilişkisini inceler. Sonuçlar saha RF saldırısı, ticari RAN
genellemesi veya QoS garantisi değildir. E2 KPM'den canlı inference ve E2 RC
kontrolü uygulanmış değildir; live backend mevcut FlexRIC/E2 hattını doğrular,
AI kararları yine kapanmış telemetri pencerelerinde üretilir.

## Kontrollü suite

`run_adversarial_suite.py` aynı model, seed/run, UE sayısı, süre ve olay
takvimiyle koşul setini eşler. `--modes` altı modu kabul eder: `none`,
`random`, `bias`, `fgsm`, `pgd`, `exact`. Varsayılan set altısını da içerir;
`none` zorunludur ve bir kere çalıştırılır. `--epsilon` ham SINR bias sınırıdır
(0–5 dB). Epsilon sıfır deneyi, bias olmayan kontrol niteliğinde ayrı bir suite
olarak çalıştırılmalıdır; farklı epsilon/seed/backend sonuçları birbirine
karıştırılmamalıdır. Suite en az 3, en fazla 120 UE ve en az 3 saniye ister.

```bash
python3 run_adversarial_suite.py --backend native --duration 3 --ues 6 \
  --seed 41 --run 1 --epsilon 2 --modes none random bias fgsm pgd exact \
  --access two_cell --predictor ridge --output results/suite-e2

python3 run_adversarial_suite.py --backend native --duration 3 --ues 6 \
  --seed 41 --run 1 --epsilon 0 --modes none random bias fgsm pgd exact \
  --output results/suite-e0
```

Erişim seçenekleri `two_cell`, `target_only`, `best_only`'dır. `--predictor
persistence` aynı ridge şemasını koruyan, sıfır residual ağırlık ve bias ile
mevcut SINR'ı tahmin eden taban çizgisini suite boyunca kullanır. Model dosyası
ve hash'i her suite manifestinde saklanır.

`fgsm` tek adım kullanır. `pgd` varsayılan olarak 10 projeksiyon adımı ve 5
başlangıç kullanır; başlangıçlar arasındaki en iyi bulunan iterat korunur.
Adımlar/başlangıç sayısı `--steps`, `--restarts` ile ayarlanır. Bu yöntemler
yerel modeldeki bir pencerenin tahmin sıralamasına göre tasarlanmıştır.

`--max-step-db` bir pencerenin bias değişimini önceki tick'teki bias'a göre
sınırlar. Saldırı etkisiz kaldığında (olay dışında veya hücre saldırı
desteğinde değilken) bias sıfırlanır; dolayısıyla bu seçenek bütün koşu için
kesintisiz bir slew limiti tanımlamaz.

`exact` ve optimizasyon denetimindeki optimum, geçmiş bias'ı sabit tutup mevcut
pencerenin erişilebilir hücre bias'ları üzerinde hedef-birinci tahmin marjını
tek pencere için çözer. Çok pencereli yörünge, QoS veya kontrol başarısı
optimizasyonu değildir.

## Robust bütçe

`--robust-budget-db B` politika kararında her hücrenin bir-adımlı forecast
aralığını hesaplar. Mevcut ve önceki pencere SINR bias'larının birbirinden
bağımsız olarak `[-B, B]` içinde değişebileceğini varsayar; handover önerisi
ancak en kötü durum skor kazancı histerezis eşiğini geçerse verilir. Aksi halde
politika `hold` eder. Bu savunma saldırı/oyun teorisi optimizasyonu değildir.

Aralık, model parametrelerinin ve diğer telemetri özelliklerinin güvenilir
olduğunu varsayar. Yalnız bir-adımlı skor farkını sınırlar; gerçek SINR, QoS,
throughput, handover teyidi veya farklı politika yörüngesindeki sonraki
kararları sertifikalandırmaz. `--robust-budget-db` 0–5 dB kabul eder. Çalışan
policy kararlarında bütçe ve `certified_gain_lower_db` kaydedilir; tahmin CSV'si
nokta tahminlerini içerir.

## Bağımsız eğitim ve test

Pilot bölmesi aynı koşudaki UE gruplarını ayırır ve `same_run_held_out_UE_pilot`
olarak raporlanır; bağımsız koşu doğrulaması değildir. Bağımsız değerlendirme
için train, validation ve test run'larını ayrı verin. Native data kaynağına izin
vermek için `--allow-native` gerekir; bu bayrak live-E2 doğrulaması sağlamaz.
Alpha grid yalnız training fit'leri ve validation MAE ile seçilir; son model
training setinde yeniden fit edilir. Test seti seçime girmez:

```bash
python3 train_ai.py --allow-native \
  --run-dir results/native-clean-seed41 \
  --validation-run-dir results/native-clean-seed53 \
  --test-run-dir results/native-clean-seed67 \
  --alpha-grid 0.1 1 10 100 1000 \
  --output ai/artifacts/native-seed41-val53-test67
```

Train/validation/test koşuları farklı seed taşımalı; tekrarlı kaynak, ortak CSV
SHA256 veya split'ler arası ortak seed reddedilir. Validation split'i hem train
hem testten ayrıdır. Provenance train, validation ve test kaynaklarını ayrı
alanlarda tutar. Üç seed burada örnek komut değerleridir; bağımsız tekrarların
varlığı tek başına geniş dış geçerlilik kanıtı değildir.

## Analiz ve kontrol doğrulaması

```bash
python3 analyze_experiments.py results/suite-e2 results/suite-e0 \
  --output results/analysis-local
python3 summarize_campaign.py results/analysis-local/run_summary.csv \
  --output results/analysis-local/statistics
python3 check_control.py results/suite-e2/suite-e2-pgd --native
python3 evaluate_replay.py --model ai/artifacts/native-seed41-val53-test67/model.json \
  --run-dir results/native-clean-seed67 --allow-native --epsilon 2 \
  --access two_cell --robust-budget-db 1 --output results/replay-seed67
```

Analiz paired `none` koşusuna göre run özeti üretir. `summarize_campaign.py`
seed kümeli bootstrap aralığı hesaplar; aynı seed içindeki tekrarlı suite'leri
önce ortalar ve p-değeri üretmez. İki bağımsız seed'den azında CI üretmez; iki
seed de belirsiz aralıktır. Native/live, predictor, access, robust budget,
defense, UE/süre/epsilon strata'ları ayrı tutulmalıdır. `off` ile robust bütçe
`0` farklıdır: off savunmayı kapatır, 0 ise sıfır bias aralığını sertifikalandırır.

`evaluate_replay.py` model provenance'ını test run'larına göre denetler; modelde
provenance yoksa yalnız `--allow-unverified-split` açıkça verildiğinde devam eder.
Replay ridge ve persistence'ı altı modda, ayrı run/predictor/access/bütçe
satırlarıyla raporlar. Hedef, temiz telemetriden türetilen sonraki-window SINR
etiketidir. Sentetik in-memory perturb ölçülmüş radyo/uygulama trafiğini
değiştirmez; bu analiz nedensel QoS/throughput etkisi veya handover başarısı
ölçmez, ağ kontrolü uygulamaz.

Kontrol doğrulaması altyapı kanıtını (tamamlanma, kayıt biçimi, referanslar)
kontrol sonucu (submitted, confirmed, rejected/unconfirmed) olarak ayrı raporlar.
`passed` ayrıca en az bir submission ve tüm submission'ların teyidini gerektiren
sıkı başarı sinyalidir. Daha sonraki target-connected olayı o anda teyittir; tüm
pencere boyunca hedef hücre kullanımı veya QoS iyileşmesi değildir.

## Zaman eşlemesi ve eksik alanlar

Model kararı kapanan 100 ms pencerenin sonundaki `decision_time_s` ile
zamanlanır. Attack audit'teki `event_active` ve `input_perturbed` aynı kapanan
pencerenin saldırı/model girdisini açıklar. `analyze_experiments.py`, bu AML
alanlarını uygulama penceresine aynı-window etiketi olarak ekler. `prior_decision_*`
alanları ise uygulama penceresinin `window_start_s` anına eşleşen önceki
kararıdır. Sonraki kontrol teyidi olay zamanıyla raporlanır; başlangıçtan sona
hedef hücrede kalındığını ima etmez.

Radyo tablosundaki `aml_audit_available=0` audit eşleşmesinin bulunmadığı
anlamına gelir; AML alanlarındaki boş dizgeler sıfır olarak yorumlanmamalıdır.
Eş audit kaydında `event_active=0` ve `input_perturbed=0` pencerenin açıkça
pasif/bozulmamış olduğunu gösterir. Uygulama tablosundaki `aml_*_same_window`
bayrakları join sırasında eş audit yoksa 0'a doldurulur; bu yüzden tek başına
audit varlığı kanıtı değildir. Eş audit kaydında boş `active_event_ids`, mode
`none` olsa da, o girdiye uygulanan etkin evasion olmadığını gösterir.
`prior_decision_time_s` boşsa başlangıçta eş karar yoktur;
boş `prior_decision_action` `hold` anlamına gelmez.

Bu protokol kısa, sentetik pilotları düzenli ve denetlenebilir biçimde
karşılaştırmayı amaçlar; sonuç iddiası yerine geçmez.


## Kaynak sürümleri ve denetim kapsamı

Campaign kaynak dosyalarını işler arasında hash ile denetler. Çalışırken kaynak
kodunu düzenlemeyin; sürüm değişiminden sonra devam etmek gerekiyorsa değişikliği
inceleyip `--allow-code-change` ile açık bir revizyon sınırı kaydedin. Bu seçenek
eski koşuları yeni kodla yeniden üretilmiş saymaz. Analiz, suite manifestindeki
kaynak hash'lerini provenance'a taşır; mevcut çalışma ağacının hash'ine eşitliği
zorunlu tutmaz. Böylece eski deneyler yeni doğrulayıcıyla incelenebilir.

Simülasyon/çıkarım kaynakları ve binary/image kimliği için ayrı
`experiment_pipeline_sha256` üretilir; farklı fingerprint'ler istatistikte
birleştirilmez. Yeni uygulama tablosunda `aml_input_audit_available`, audit join'inin
bulunup bulunmadığını gösterir. Post-warmup karar/audit kapsamı eksikse analiz
geçmez; ilk warmup penceresinde boş audit, temiz ölçüm anlamına gelmez.

`ai_shadow_status.json` içindeki `batch_processing` duvar saati ölçümü,
poll sonrasındaki saldırı, referans/gözlenen politika ve CSV yayınını kapsar.
Telemetri üretim/bekleme ve RRC teyidini kapsamaz; gerçek near-RT uçtan uca gecikme
veya deadline karşılama kanıtı değildir.
