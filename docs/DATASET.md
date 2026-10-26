# Veri sözlüğü ve kullanım

Bir suite `none` ve seçilen evasion koşullarını eşler. Desteklenen modlar
`none`, `random`, `bias`, `fgsm`, `pgd`, `exact`'tır; varsayılan altısıdır.
Suite içindeki seed/run, UE sayısı, süre, model, olay zamanları ve ayarlar
sabit tutulur. Ayrıntılı yöntem ve komutlar [EVALUATION.md](EVALUATION.md)'de.

## Tablolar

`application_dataset.csv`: run × UE × 100 ms; ölçülen PacketSink RX byte,
uygulama goodput'u, konum/hız, gerçek RRC durumu ve deney etiketleri.
Toplam veri ve goodput hesaplamaları bu tabloyu kullanır.

`radio_dataset.csv`: run × UE × NR hücre × 100 ms; radyo ölçümleri ve modelin
gördüğü özelliklerin audit'i. Uygulama değerleri dört hücrede tekrarlanır;
UE uygulama değerleri bu tablodan doğrudan toplanmaz.

`run_summary.csv`: koşu başına warmup dışı RX byte, toplam ağ goodput'u,
eşlenmiş temiz koşuya göre byte farkı, saldırı ve kontrol metrikleri.

`target_gap.csv`: aktif UE-penceresi başına temiz birinci hücre eksi hedef
hücre tahmini, saldırı öncesi ve sonrası. Son farkın negatif olması hedefin
eski birinciyi geçtiği anlamına gelir. Eşitlikler sıralama tie-break'ine bağlıdır.

## Ortak alanlar

| Alan | Anlam |
|---|---|
| run_id / suite_id | Koşu kimliği / eşlenmiş koşul setini bağlayan suite kimliği |
| backend | live veya native; farklı backend'ler aynı performans popülasyonu değildir |
| experiment_seed / experiment_run | ns-3 RNG seed ve run |
| experiment_condition | none / random / bias / fgsm / pgd / exact; seçilen koşullar |
| epsilon_db | Suite'in ham SINR bias sınırı; none koşulunda fiili delta sıfırdır |
| model_sha256 | Gerçek kullanılan model dosyasının SHA256 hash'i |
| window_start_s / window_end_s | Simülasyon saatinde pencere başlangıcı/sonu; duvar saati değildir |
| ue_imsi / nr_cell_id | UE ve ölçülen NR hücre kimlikleri |
| rx_bytes / app_goodput_mbps | UE uygulamasının o penceredeki RX byte / Mbps |
| ue_rx_bytes / ue_app_goodput_mbps | Radyo tablosuna tekrar edilen aynı uygulama ölçümleri |
| is_warmup / ue_is_warmup | Isınma dönemi; dosyada tutulur, özet metriklerden çıkarılır |
| traffic_profile / direction | TCP bulk, UDP bursty video, UDP telemetry / DL veya UL |
| x_m, y_m, speed_mps | UE konumu (m), hız (m/s); radyo tablosunda ue_ önekiyle |
| ue_nr_rrc_cell_id / ue_nr_rrc_state | O pencerenin gerçek NR RRC hücre/durum gözlemi |
| ue_control_required | Harici kontrol bariyerinin komut beklediği pencere |
| attack_present / attack_type | Eski UDP yük saldırısı etiketleri; AML etiketleri değildir |
| aml_event_active | UE için o anda evasion takvimi aktif mi? |
| aml_input_perturbed | Bu pencere veya önceki pencere bias'ı modele etki ediyor mu? |
| aml_audit_available | Bu radyo penceresi için attack audit eşleşmesi var mı? 0 ise audit yoktur; diğer AML boş alanlarını sıfır saymayın. |
| aml_input_event_active_same_window / aml_input_perturbed_same_window | Uygulama tablosunda aynı kapanan pencereye katılmış bayraklar. Eş audit yoksa birleştirme 0 yazar; bu tabloda 0 tek başına audit varlığını kanıtlamaz. |
| prior_decision_time_s / prior_decision_action | Uygulama penceresi başlangıcına eşleşen karar. Boş zaman eşleşme olmadığını, boş action ise `hold` garantisi olmadığını belirtir. |
| prior_decision_target_connected_confirmed / prior_decision_confirmation_time_s | Önceki kararın daha sonraki hedef-bağlantı teyidi ve olay zamanı; tüm pencere boyunca serving-cell durumu değildir. |

## Radyo ve AML alanları

`sinr_*_db`: ham ns-3 SINR örneklerinin pencere ortalama/std/min/max/son değeri;
`sinr_sample_count` örnek sayısıdır. `cell_dl_*`: hücre bazında PHY transport
block sayısı, bozuk block oranı, byte, başarılı byte, MCS, RV, alıcı SINR ve
TBLER özetleri. Bunlar UE'ye özgü goodput ölçümleri değildir.
`last_recorded_path_cell_id` ve ilgili path alanları kayıtlı path olaylarını
özetler; gerçek kontrol teyidi yerine kullanılamaz.

Radyo tablosunda `aml_audit_available=0` olan satırda model audit'i yoktur
(örneğin ilk pencerede önceki SINR bulunmadığında); boş AML alanlarını sıfır
saldırı diye doldurmayın. Uygulama tablosundaki `aml_*_same_window` bayrakları
audit ile join edilir ve eş kayıt yoksa 0 olarak doldurulur; bunlar audit
mevcudiyeti için kullanılmamalıdır.
Eşleşmiş audit'te `event_active=0`, evasion'ın bu pencere kararında etkin
olmadığını açıkça belirtir. `active_event_ids` boş dizgesi model girdisine
uygulanan etkin evasion olayı olmadığını gösterir (mode `none` iken takvimde
olay bulunsa da boş kalır); audit satırının kendisi varsa bu değer eksik alanla
aynı değildir.
`aml_mode`, `aml_epsilon_db`, `aml_active_event_ids` yöntem/bütçe/olay kimliğidir.
`aml_delta_sinr_db` ve `aml_previous_delta_db` mevcut ve önceki pencere bias'ıdır.
`aml_raw_sinr_mean_db` ham, `aml_model_sinr_mean_db` gözlenen ortalamadır.
`aml_clean_prediction_db` ve `aml_observed_prediction_db` aynı ağ durumunda
ham ve bozulmuş girdilerle tahminlerdir. `aml_clean_best_cell` ve
`aml_attack_target_cell` temiz birinci ve hedef hücredir.

`aml_clean_` ve `aml_model_` önekli sekiz özellik:

1. sinr_mean_db: pencere ortalaması (dB).
2. sinr_last_db: son örnek (dB).
3. sinr_std_db: pencere standart sapması (dB).
4. mean_change_db: mevcut eksi önceki ortalama (dB).
5. last_minus_mean_db: son örnek eksi ortalama (dB).
6. cell_dl_tb_count: hücre DL transport block sayısı.
7. cell_dl_corrupt_fraction: bozuk DL block oranı; örnek yoksa boş.
8. cell_corrupt_fraction_missing: önceki oranın eksikliği (0/1).

Eksik değerler CSV'de boş bırakılır. Model eğitim medyanlarıyla doldurur;
radyo ölçümü üretilmiş gibi sıfırla doldurulmaz. Saldırı bütün SINR örneklerine
pencere başına sabit bias uygular; std ve last-minus-mean değişmez. Önceki
bias'ın feature farkına etkisi bir sonraki pencerede görülebilir. Saldırı
etkisiz olduğunda bias sıfırlanır.

Zamanlama: audit `decision_time_s` kapanmış 100 ms pencerenin sonudur. Evasion
olay maskesi bu karar zamanında değerlendirilir. `analyze_experiments.py` aynı
pencere AML bayraklarını uygulama satırına ekler; `prior_decision_*` ise
uygulama penceresi `window_start_s` ile eşleşen önceki kararı tanımlar. Sonraki
target-connected teyidi yalnızca teyit anındaki olaydır.

## Bölme ve istatistik

Bağımsız tune/test için `train_ai.py` komutuna ayrı `--run-dir`,
`--validation-run-dir` ve `--test-run-dir` verin. Native kaynak için
`--allow-native` zorunludur ve live-E2 doğrulaması anlamına gelmez.
`--alpha-grid` her alpha'yı yalnız train'de fit eder, validation MAE ile seçer;
son modeli train örneklerinde yeniden fit eder. Test seçime katılmaz.
Train/validation/test seed'leri farklı olmalı; ortak CSV SHA256, tekrarlı kaynak
veya seed eksikliği/örtüşmesi reddedilir. Kaynak provenance'ı ayrı tutulur.
Varsayılan aynı-run UE bölmesi pilot olarak etiketlenir ve bağımsız run
değerlendirmesi sayılmaz.
Aynı UE-zamanın hücre satırlarını veya komşu zaman pencerelerini rastgele
train/test'e dağıtmak sızıntıya yol açabilir. Tüm eşlenmiş koşulları aynı
bölmede tutun. Aynı seed ile farklı epsilon suite'lerinin temiz koşuları
bağımsız tekrar değildir. Etkiyi suite içindeki temiz koşuya göre hesaplayın;
çoklu bağımsız seed sonuçlarını ayrıca değerlendirin. Robust bütçenin `off`
olmasıyla `0` ayrı koşullardır; `off` savunmasız politika, `0` sıfır bias
aralığına karşı sertifikalı politikadır. Access ve predictor da ayrı strata'dır.
Bootstrap özeti iki bağımsız seed'den azında CI üretmez. Şimdilik yalnız kısa
pilot sonuçlarından anlamlılık/genelleme veya saldırıdan korunma iddiası yoktur.


`aml_input_audit_available` uygulama penceresinin aynı bitiş zamanında model audit'i
bulunduğunu gösterir. Post-warmup karar/audit kapsamı eksik koşular doğrulamayı
geçmez. `experiment_pipeline_sha256` simülasyon/çıkarım kaynağı ve binary/image
kimliği için fingerprint'tir; farklı fingerprint'ler seed istatistiklerinde
birleştirilmez. Tam kaynak hash'leri ayrıca provenance içinde korunur.

`bearer_intervals.csv` mevcut PDCP/RLC izlerinin hiç kayıt üretmediği koşuda
başlık içerip sıfır satır taşıyabilir. `quality_report.json` içindeki
`bearer_intervals_available` ve `bearer_intervals_by_layer` bunu açıklar. Eksik
ham PDCP/RLC dosyası, mevcut fakat boş dosyayla aynı durum değildir; zorunlu
ham dosya eksikse dışa aktarma başarısız olur. Boş tabloya hayali ölçüm eklenmez.
