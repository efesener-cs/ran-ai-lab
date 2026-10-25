# Veri sözlüğü ve kullanım

Her suite dört eşlenmiş koşu içerir: none, random, fgsm, pgd. Suite içindeki seed,
UE sayısı, süre, model, saldırı zamanları ve kontrol ayarları sabittir.

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
| run_id / suite_id | Koşu kimliği / dört koşulu bağlayan suite kimliği |
| backend | live veya native; farklı backend'ler aynı performans popülasyonu değildir |
| experiment_seed / experiment_run | ns-3 RNG seed ve run |
| experiment_condition | none / random / fgsm / pgd |
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

## Radyo ve AML alanları

`sinr_*_db`: ham ns-3 SINR örneklerinin pencere ortalama/std/min/max/son değeri;
`sinr_sample_count` örnek sayısıdır. `cell_dl_*`: hücre bazında PHY transport
block sayısı, bozuk block oranı, byte, başarılı byte, MCS, RV, alıcı SINR ve
TBLER özetleri. Bunlar UE'ye özgü goodput ölçümleri değildir.
`last_recorded_path_cell_id` ve ilgili path alanları kayıtlı path olaylarını
özetler; gerçek kontrol teyidi yerine kullanılamaz.

`aml_audit_available=0` olan satırda model audit'i yoktur (özellikle ilk
pencerede önceki SINR yoktur); boş AML alanlarını sıfır saldırı diye doldurmayın.
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
pencere başına sabit bias uygular; std ve last-minus-mean değişmez. Geçmiş
etkisi saldırı bittikten sonra bir pencere sürebilir.

## Bölme ve istatistik

Eğitim/test bölmesini bağımsız koşu/seed ve deney grupları üzerinden yapın.
Aynı UE-zamanın hücre satırlarını veya komşu zaman pencerelerini rastgele
train/test'e dağıtmak sızıntıya yol açabilir. Tüm eşlenmiş koşulları aynı
bölmede tutun. Aynı seed ile farklı epsilon suite'lerinin temiz koşuları
bağımsız tekrar değildir. Etkiyi suite içindeki temiz koşuya göre hesaplayın;
çoklu bağımsız seed sonuçlarını ayrıca değerlendirin. Şimdilik yalnız kısa
pilot sonuçlarından anlamlılık/genelleme veya saldırıdan korunma iddiası yoktur.
