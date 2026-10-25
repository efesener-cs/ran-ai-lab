# RAN AI modeli ve saldırı deneyleri için araştırma — 25 Ekim 2026

## Mevcut durum

Canlı deneme /work/flexric yolunda cache bulunamadığından başlamadı.
run_live.py bind-mount hedeflerini aramaya ekleyecek şekilde güncellendi.
discover_sources.py uyumlu kaynak/build dizinlerini bulur; tek aday yoksa
rastgele seçim yapmadan yolları bildirir. E2AP_V1 / KPM_V3_00 denetlenir.
Eski cache yolu artık kullanılmaz; portable_build.py ayrı bir build oluşturur.
Üç discovery testi geçti. Bu testler canlı E2 bağlantısını doğrulamaz.
Kaynaklar container'a hiç bağlanmamışsa otomatik keşif onları oluşturmaz;
bu durumda kaynakların container içinde sağlanması gerekir.

## Hazır modeller ve deney ortamları

1. AdvO-RAN: https://github.com/Restuccia-Group/AdvO-RAN
   README PPO victim policy snapshotlarını (actor/value/optimizer npz),
   encoder, learned perturbator ve robust training akışını listeliyor.
   attack_wa.py PGD tarzında actor saldırısı sunuyor.
   Makale: https://mentis.info/wp-content/uploads/2025/10/Tackling_AdvDRL_MobiHoc_2025.pdf
   Colosseum emülatörü üzerinde slicing/scheduling DRL xApp'lerine KPM
   pertürbasyonlarını değerlendiriyor. Repo çalıştırılıp checkpointlerin
   mevcut sistemde yüklendiği henüz doğrulanmadı. Girdi sırası, normalizasyon,
   zaman penceresi, encoder ve PRB/scheduler eylemlerinin anlamı eşleşmeden
   hazır policy'yi mevcut senaryoya bağlamak geçerli değildir. Mevcut senaryo
   bu PRB/slice kontrol arayüzünü sunuyor varsayılmamalıdır.

2. MalO-RAN: https://github.com/wineslab/mal-o-ran
   How to Poison an xApp (Computer Networks, 2025). DRL xApp eğitiminde
   backdoor poisoning; SleeperNets ve TrojDRL deneyleri, Colosseum üzerinde
   live O-RAN değerlendirmesi. Eğitim verisini değiştirebilme varsayımı
   gerektirir; inference sırasında CSV'ye rastgele gürültü eklemek eşdeğeri değildir.

3. System-level Analysis of Adversarial Attacks and Defenses on Intelligence
   in O-RAN based Cellular Networks:
   https://arxiv.org/html/2402.06846v1
   Fiziksel over-the-air LTE/5G testbed; interference sınıflandıran CNN/DNN
   xApp'lerinde spectrogram/KPM girdilerine FGSM/PGD saldırıları. Hem model
   sonucunu hem ağ performansını ölçer. Bu bir salt ns-3 simülasyonu değildir.

4. ns-o-ran-gym: https://github.com/wineslab/ns-o-ran-gym
   Gymnasium arayüzü; TrafficSteeringEnv, EnergySavingEnv, KPM datalake ve
   dosya üzerinden eylem aktaran ActionController. Bu bir ortam altyapısıdır;
   her senaryoda hazır ve başarılı policy bulunduğu varsayılmamalıdır.
   Dosya kontrol yolunu gerçek E2 RC kontrolü olarak etiketlemeyin.

5. NetsLab RRC Signalling Storm Dataset:
   https://netslab.ucd-cs.ie/rrc-signalling-storm-dataset/
   OAI tabanlı fiziksel testbed'de UE reboot ve DU restart kaynaklı handover
   storm deneyleri. PHY/MAC ölçümleri de topluyor. Mevcut ns-3 ideal RRC
   davranışı gerçek O-CU/O-DU CPU yükünü veya NAS prosedürlerini doğrulamaz.

## Deneyler: öneri ile literatürdeki uygulamayı ayırma

- Temiz ağ + temiz model girdisi: bütün karşılaştırmaların baseline'ı.
- Meşru yoğun trafik: false positive ve kapasite etkisini ayıran kontrol grubu.
- Kontrollü UDP hacim yükü: sınırlı sayıdaki simüle UE'den, belirli hedef,
  başlangıç/bitiş ve hızla. Gözlenen ölçümün değişmesi fiziksel/ağ etkisidir.
- FGSM/PGD evasion: eğitilmiş hedef modelin yalnız erişilebilir girdilerine,
  belirtilmiş birim ve bütçeyle müdahale. Modelde karar hatası ve QoS etkisi
  ayrı kaydedilmeli. KPM değiştirmek RF sinyalini değiştirmek değildir.
- Replay/stale telemetry: eski gözlemi yeni karar anında sunmak. Bu, burada
  önerilen bir deneydir; yukarıdaki her makalede uygulandığı iddia edilmiyor.
- Eksik/gecikmiş telemetry: iletişim hatası kontrolü ile kasıtlı saldırı
  etiketini ayrı tutmak gerekir; timeout ve fallback kararı ölçülmeli.
- Poisoning/backdoor: ayrı eğitim hattı, trigger ve hedef davranış tanımı.
- RRC/handover storm: daha gerçekçi kontrol düzlemi modeli/testbed gerektirir;
  mevcut ideal RRC pilotuna tam signaling-storm deneyi denmemeli.
- RF jamming: uygun interference/spectrum modeli veya SDR testbed gerektirir;
  sayısal SINR alanını CSV içinde azaltmak yalnız telemetry manipulation'dır.

## hping3 neden doğrudan eklenmiyor?

Mevcut ns-3 UE IP adresleri Linux container ağına otomatik bağlı değildir.
Hosttan/container'dan gönderilen paketler, sırf ns-3 de aynı container içinde
çalışıyor diye simüle RAN'dan geçmez. E2 socket bağlantısı user-plane köprüsü
değildir. RIC'in Linux IP'sine yük göndermek RIC host DoS deneyi olur.

Gerçek paketleri simülasyona sokmak için TapBridge/FdNetDevice, uygun rota ve
zaman senkronizasyonu gerekir:
https://www.nsnam.org/docs/models/html/tap.html
https://www.nsnam.org/docs/release/3.44/models/html/emulation-overview.html

İlk hacim deneyi için öneri, yükü ns-3 uygulamaları içinde üretmek: hız,
katılımcı UE sayısı, süre ve hedef ölçülebilir; simülasyon saatiyle etiketlenir.
Bu, Linux SYN backlog veya web sunucusu kaynak tüketimini modellemez.

## Projeye önerilen sıra

1. Mevcut canlı E2/KPM pilotunu doğrula.
2. AdvO-RAN'ı kendi gözlem/eylem ortamında model/saldırı baseline'ı olarak
   yeniden üret; checkpoint ve dependency sürümlerini sabitle.
3. Mevcut simülasyona uyarlanacak karar görevi olarak traffic steering'i
   değerlendir. Desteklenen eylemler, gerçek E2 RC veya dosya kontrol yolu
   açıkça belgelenmeli; policy gerekiyorsa bu ortamda yeniden eğitilmeli.
4. Temiz/gürültü/evasion/hacim koşullarını aynı seed ve trafik altında eşleştir.
   Poisioning/backdoor hattını ayrıca ele al.
5. CSV'de gerçek clean KPM, modele sunulan KPM, eylem, gerçekleşen QoS,
   attack_type, erişilebilir özellikler, epsilon birimi, model/version,
   seed ve zaman aralığını tut. Bu alanların hepsini model girdisi yapma.
6. Seed/koşu bazlı ayrım kullan. Ağ etkisini replay verisinden tek başına
   çıkarsama; kapalı döngüde eylemin gerçekten uygulandığını doğrula.
