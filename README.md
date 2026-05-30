DDoS-Shield 

DDoS-Shield, ağ trafiğini gerçek zamanlı olarak izlemek, analiz etmek ve potansiyel DDoS saldırılarını (SYN Flood, Hacimsel Spike vb.) tespit etmek için geliştirilmiş, Rust diliyle yazılmış yüksek performanslı bir izleme aracıdır.

Temel Özellikler

Gerçek Zamanlı Analiz: Ağ trafiğini pnet kütüphanesi ile düşük gecikme süresiyle işler.

Anomali Tespiti:

Volumetric Spike: Ani trafik patlamalarını tespit eder.

SYN Flood: TCP SYN paketlerini izleyerek saldırıları belirler.

Single IP Flood: Tek bir kaynaktan gelen anormal trafik yoğunluğunu saptar.

Güvenli Tasarım: OOM (Out-of-Memory) hatalarını önlemek için tamponlu kanal (sync_channel) yapısı kullanır.

Terminal Arayüzü: Renkli ve anlaşılır terminal çıktıları.

Gereksinimler

Programın çalışması için aşağıdaki bağımlılıkların sisteminizde kurulu olması gerekir:

Rust & Cargo: rustup.rs üzerinden kurulum yapabilirsiniz.

WinPcap / Npcap: Proje Windows üzerinde çalıştığı için ağ trafiğini yakalayabilmek adına Npcap sürücülerine ihtiyaç duyar 

 Çalıştırma

Ağ paketlerini yakalamak düşük seviyeli erişim gerektirdiği için programı Yönetici olarak çalıştırmanız zorunludur.

Program başladığında sisteminizdeki ağ adaptörlerini listeleyecektir. İzlemek istediğiniz adaptörün numarasını girerek süreci başlatabilirsiniz.

⚠️ Önemli Notlar

Bu araç, saldırıları tespit etmek amacıyla geliştirilmiştir, saldırıları engellemek için bir "Firewall" yerine geçmez.
