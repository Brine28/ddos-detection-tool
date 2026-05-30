use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use std::io::{self, Write};
use std::process;
use std::sync::mpsc;
use std::thread;

// --- MODÜLLER ---

/// Veri modelleri ve yapıları
mod models {
    use serde::Serialize;
    use std::net::Ipv4Addr;

    #[derive(Debug, Clone)]
    pub struct PacketInfo {
        pub src_ip: Ipv4Addr,
        pub dst_ip: Ipv4Addr,
        pub size: usize,
        pub is_syn: bool,
    }

    #[derive(Serialize, Clone, Debug, PartialEq)]
    pub enum Severity {
        Low,
        Medium,
        High,
        Critical,
    }

    #[derive(Serialize, Clone, Debug)]
    pub struct Alert {
        pub timestamp: String,
        pub adapter: String,
        pub severity: Severity,
        pub anomaly_type: String,
        pub score: f64,
        pub threshold: f64,
        pub description: String,
    }
}

/// Terminal arayüzü ve renklendirme işlemleri
mod ui {
    use super::models::{Alert, Severity};
    use crossterm::{
        execute,
        style::{Color, Print, ResetColor, SetForegroundColor},
    };
    use std::io::stdout;

    pub fn print_logo() {
        let logo = r#"
  ___  ___       ___   ____     ____  _   _ _____ _____ _     ____  
 |  _ \|  _ \ ___/ ___| / ___|   / ___|| | | |_   _| ____| |   |  _ \ 
 | | | | | | |___| |  _  \___ \  \___ \| |_| | | | |  _| | |   | | | |
 | |_| | |_| |   | |_| |  ___) |  ___) |  _  | | | | |___| |___| |_| |
 |____/|____/     \____| |____/  |____/|_| |_| |_| |_____|_____|____/ 
                                                                      
        "#;
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::Cyan),
            Print(logo),
            ResetColor,
            Print("\n[+] Gerçek Zamanlı Ağ Koruma Modülü Başlatılıyor...\n\n")
        );
    }

    pub fn print_alert(alert: &Alert) {
        let color = match alert.severity {
            Severity::Low => Color::Green,
            Severity::Medium => Color::Yellow,
            Severity::High => Color::Magenta,
            Severity::Critical => Color::Red,
        };

        // DÜZELTME: {:#?} formatı yerine {:?} kullanıldı (Gereksiz satır atlamaları önlendi)
        let _ = execute!(
            stdout(),
            SetForegroundColor(Color::DarkGrey),
            Print(format!("[{}] ", alert.timestamp)),
            SetForegroundColor(color),
            Print(format!("[{:?}] ", alert.severity)),
            SetForegroundColor(Color::White),
            Print(format!("{} - ", alert.anomaly_type)),
            SetForegroundColor(Color::Red),
            Print(format!("Skor: {:.2} (Eşik: {:.2}) ", alert.score, alert.threshold)),
            SetForegroundColor(Color::Reset),
            Print(format!("=> {}\n", alert.description)),
        );
    }
}

/// Ağ paketlerini yakalama ve ayrıştırma
mod network {
    use super::models::PacketInfo;
    use pnet::packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ipv4::Ipv4Packet,
        tcp::{TcpFlags, TcpPacket},
        Packet,
    };
    use std::sync::mpsc::SyncSender;

    // DÜZELTME: OOM koruması için Sender yerine sınırlı tamponlu SyncSender kullanılıyor
    pub fn process_packet(packet: &[u8], tx: &SyncSender<PacketInfo>) {
        if let Some(eth) = EthernetPacket::new(packet) {
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    let mut is_syn = false;
                    
                    // TCP kontrolü ve SYN bayrağı tespiti
                    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            is_syn = (tcp.get_flags() & TcpFlags::SYN) != 0;
                        }
                    }

                    let pkt_info = PacketInfo {
                        src_ip: ipv4.get_source(),
                        dst_ip: ipv4.get_destination(),
                        size: packet.len(),
                        is_syn,
                    };

                    // DÜZELTME: try_send kullanıyoruz. Böylece çok şiddetli DDoS anında analiz threadi 
                    // yetişemezse paketler RAM'i şişirmeden drop edilir, programın çökmesi engellenir.
                    let _ = tx.try_send(pkt_info);
                }
            }
        }
    }
}

/// Trafik analizi, istatistik ve anomali tespiti
mod analyzer {
    use super::models::{Alert, PacketInfo, Severity};
    use std::collections::{HashMap, VecDeque};
    use std::sync::mpsc::{Receiver, Sender};
    use std::time::{Duration, Instant};

    const WINDOW_DURATION_SEC: u64 = 1;
    const HISTORY_SIZE: usize = 10;
    
    const MIN_PACKET_THRESHOLD: u64 = 500; 
    const SPIKE_MULTIPLIER: f64 = 3.0;     
    const SYN_FLOOD_THRESHOLD: u64 = 200;  
    // DÜZELTME: False-positive'leri (video/dosya indirme) önlemek için eşik artırıldı
    const SINGLE_IP_MAX_PPS: u64 = 1000;    

    struct WindowStats {
        packet_count: u64,
        byte_count: u64,
        syn_count: u64,
        ip_counts: HashMap<std::net::Ipv4Addr, u64>,
    }

    impl WindowStats {
        fn new() -> Self {
            Self {
                packet_count: 0,
                byte_count: 0,
                syn_count: 0,
                ip_counts: HashMap::new(),
            }
        }
    }

    pub fn start_analyzer(
        adapter_name: String,
        rx: Receiver<PacketInfo>,
        alert_tx: Sender<Alert>,
    ) {
        let mut current_window = WindowStats::new();
        let mut history: VecDeque<u64> = VecDeque::with_capacity(HISTORY_SIZE);
        let mut window_start = Instant::now();

        // Olay korelasyonu (Spam engelleme) için son alarm kayıtları
        let mut last_alert_times: HashMap<String, Instant> = HashMap::new();

        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(packet) => {
                    current_window.packet_count += 1;
                    current_window.byte_count += packet.size as u64;
                    if packet.is_syn {
                        current_window.syn_count += 1;
                    }
                    *current_window.ip_counts.entry(packet.src_ip).or_insert(0) += 1;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break, // Kanal kapandı
            }

            if window_start.elapsed() >= Duration::from_secs(WINDOW_DURATION_SEC) {
                analyze_window(
                    &adapter_name,
                    &current_window,
                    &history,
                    &alert_tx,
                    &mut last_alert_times,
                );

                if history.len() >= HISTORY_SIZE {
                    history.pop_front();
                }
                history.push_back(current_window.packet_count);

                current_window = WindowStats::new();
                window_start = Instant::now();
            }
        }
    }

    fn analyze_window(
        adapter_name: &str,
        stats: &WindowStats,
        history: &VecDeque<u64>,
        alert_tx: &Sender<Alert>,
        last_alert_times: &mut HashMap<String, Instant>,
    ) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        
        // 1. Hacimsel Spike (Volumetric Anomaly)
        if !history.is_empty() && stats.packet_count > MIN_PACKET_THRESHOLD {
            let avg_packets: f64 = history.iter().sum::<u64>() as f64 / history.len() as f64;
            
            // DÜZELTME: Ağda daha önce hiç trafik yoksa (Sıfıra bölme ve mantık hatası önlemi)
            let safe_avg = if avg_packets < 1.0 { 1.0 } else { avg_packets };
            
            let spike_ratio = stats.packet_count as f64 / safe_avg;
            if spike_ratio > SPIKE_MULTIPLIER {
                send_alert(alert_tx, last_alert_times, Alert {
                    timestamp: now.clone(),
                    adapter: adapter_name.to_string(),
                    severity: Severity::High,
                    anomaly_type: "Volumetric_Spike".to_string(),
                    score: spike_ratio,
                    threshold: SPIKE_MULTIPLIER,
                    description: format!("Ani trafik artışı algılandı. Normalin {:.1} katı! ({} pkt/s)", spike_ratio, stats.packet_count),
                });
            }
        }

        // 2. SYN Flood Tespiti
        if stats.syn_count > SYN_FLOOD_THRESHOLD {
            send_alert(alert_tx, last_alert_times, Alert {
                timestamp: now.clone(),
                adapter: adapter_name.to_string(),
                severity: Severity::Critical,
                anomaly_type: "TCP_SYN_Flood".to_string(),
                score: stats.syn_count as f64,
                threshold: SYN_FLOOD_THRESHOLD as f64,
                description: format!("Olası SYN Flood Saldırısı! Saniyede {} SYN paketi alındı.", stats.syn_count),
            });
        }

        // 3. Tekil IP Yoğunluğu (Single IP Flood)
        for (ip, count) in &stats.ip_counts {
            if *count > SINGLE_IP_MAX_PPS {
                send_alert(alert_tx, last_alert_times, Alert {
                    timestamp: now.clone(),
                    adapter: adapter_name.to_string(),
                    severity: Severity::Medium,
                    anomaly_type: "Single_IP_Flood".to_string(),
                    score: *count as f64,
                    threshold: SINGLE_IP_MAX_PPS as f64,
                    description: format!("{} adresinden anormal yoğunlukta istek geliyor ({} pkt/s).", ip, count),
                });
            }
        }
    }

    fn send_alert(alert_tx: &Sender<Alert>, last_alert_times: &mut HashMap<String, Instant>, alert: Alert) {
        let alert_key = format!("{}_{:?}", &alert.anomaly_type, &alert.severity);
        
        let should_send = if let Some(last_time) = last_alert_times.get(&alert_key) {
            last_time.elapsed() > Duration::from_secs(3) 
        } else {
            true
        };

        if should_send {
            last_alert_times.insert(alert_key, Instant::now());
            let _ = alert_tx.send(alert);
        }
    }
}

// --- ANA PROGRAM AKIŞI ---

fn main() {
    ui::print_logo();

    // 1. Sistemdeki adaptörleri bul
    let interfaces = datalink::interfaces();
    let mut valid_interfaces = Vec::new();

    println!("Sistemdeki Ağ Adaptörleri Taranıyor...\n");
    for iface in interfaces.iter() {
        if iface.ips.is_empty() {
            continue;
        }
        valid_interfaces.push(iface.clone());
        
        let ips: Vec<String> = iface.ips.iter().map(|ip| ip.ip().to_string()).collect();
        
        // DÜZELTME: Güvenli MAC adresi okuması (Panik/Derleme hatalarını önler)
        let mac_addr = iface.mac.map(|m| m.to_string()).unwrap_or_else(|| "Bilinmiyor".to_string());
        
        println!(" [{}] {} - MAC: {} - IP: {}", 
            valid_interfaces.len() - 1, 
            iface.description, 
            mac_addr, 
            ips.join(", ")
        );
    }

    if valid_interfaces.is_empty() {
        eprintln!("Hata: Dinlenebilir (IP atanmış) aktif bir ağ adaptörü bulunamadı.");
        process::exit(1);
    }

    // 2. Kullanıcıdan adaptör seçimi al
    print!("\nDinlenecek adaptör numarasını seçin (0-{}): ", valid_interfaces.len() - 1);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    let selected_index: usize = match input.trim().parse() {
        Ok(num) if num < valid_interfaces.len() => num,
        _ => {
            eprintln!("Hata: Geçersiz seçim yaptınız. Program kapatılıyor.");
            process::exit(1);
        }
    };

    let selected_interface = &valid_interfaces[selected_index];
    let interface_name = selected_interface.description.clone();

    println!("\n[+] Seçilen Adaptör: {}", interface_name);
    println!("[+] Trafik izleme ve anomali tespiti başlatılıyor... (Çıkış için Ctrl+C)\n");

    // DÜZELTME: Bellek Sızıntısı (OOM) koruması için senkron (sınırlandırılmış) kanal
    // 100,000 paketlik tampon bellek, performans ve güvenliği çok iyi dengeler.
    let (packet_tx, packet_rx) = mpsc::sync_channel(100_000);
    let (alert_tx, alert_rx) = mpsc::channel();

    // 3. Analizör Thread'ini Başlat
    let analyzer_interface_name = interface_name.clone();
    thread::spawn(move || {
        analyzer::start_analyzer(analyzer_interface_name, packet_rx, alert_tx);
    });

    // 4. Log ve UI Gösterim Thread'ini Başlat
    thread::spawn(move || {
        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("ddos_alerts.json")
            .unwrap_or_else(|err| {
                eprintln!("Uyarı: Log dosyası oluşturulamadı: {}", err);
                process::exit(1);
            });

        while let Ok(alert) = alert_rx.recv() {
            ui::print_alert(&alert);

            if let Ok(json_str) = serde_json::to_string(&alert) {
                let _ = writeln!(log_file, "{}", json_str);
            }
        }
    });

    // 5. Paket Yakalama Döngüsü (Ana Thread)
    match datalink::channel(selected_interface, Default::default()) {
        Ok(Ethernet(_tx, mut rx)) => {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        network::process_packet(packet, &packet_tx);
                    }
                    Err(e) => {
                        eprintln!("Paket yakalama hatası: {}", e);
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        }
        Ok(_) => {
            eprintln!("Hata: Desteklenmeyen kanal türü (Sadece Ethernet (DataLink) destekleniyor).");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Kritik Hata: Adaptör dinlemeye açılamadı!\nNedeni: {}\n\nÇözüm İpuçları:\n1. Programı Yönetici (Administrator) olarak çalıştırdığınızdan emin olun.\n2. Windows için Npcap'in kurulu olduğundan emin olun.", e);
            process::exit(1);
        }
    }
}