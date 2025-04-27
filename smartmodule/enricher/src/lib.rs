
use std::collections::HashMap;
use fluvio_smartmodule::{smartmodule, Result, SmartModuleRecord, RecordData};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};


#[smartmodule(array_map)]
pub fn array_map(record: &SmartModuleRecord) -> Result<Vec<(Option<RecordData>, RecordData)>> {
    
    let otx_pulse: OTXPulse = from_slice(record.value.as_ref())?;
    let mut enriched_records: Vec<(Option<RecordData>, RecordData)> = vec![];

    for result in otx_pulse.results.iter() {

        let attack_types = classify_attack_types(result);

        let attack_vectors = classify_attack_vectors(result);

        let urgency = classify_urgency(result);

        let targets = classify_targets(result);

        let locations = if result.targeted_countries.is_empty() {
            vec!["Unknown".to_string()]
        } else {
            result.targeted_countries.clone()
        };

        let expiration_date = get_expiration(result).unwrap_or_else(|| "".to_string());

        let enriched_record = EnrichedThreatRecord {
            attack_types,
            attack_vectors,
            urgency,
            targets,
            locations,
            expiration_date
        };


        let serialized_data = to_vec(&enriched_record)?;
        enriched_records.push((None, serialized_data.into()));
    }
    Ok(enriched_records)
}


/// Classification Basis Enums

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum Urgency {
    Hot,
    Cold,
    Critical,
    Medium,
    Low
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum AttackType {
    Ransomware,
    Malware,
    Ddos,
    Botnet,
    Phishing,
    Trojan,
    Spyware,
    BruteForce,
    SQLInjection,
    Unknown
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Target {
    WebApp,
    Infrastructure,
    ApiAbuse,
    IotDevices,
    UserFocused,
    EmailAttack,
    Unknown
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum AttackVector {
    Email,
    WebApplication,
    Network,
    CloudService,
    SupplyChain,
    Unknown
}


/// OTX Pulse Definition Structs

#[derive(Debug, Serialize, Deserialize)]
pub struct OTXPulse {
    pub results: Vec<OTXRecord>,
    pub count: u64,
    pub prefetch_pulse_ids: bool,
    pub t: u32,
    pub t2: f64,
    pub t3: f64,
    pub previous: Option<String>,
    pub next: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTXRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author_name: String,
    pub modified: String,
    pub created: String,
    pub revision: u64,
    pub tlp: String,
    pub public: u64,
    pub adversary: String,
    pub indicators: Vec<OTXIndicator>,
    pub tags: Vec<String>,
    pub targeted_countries: Vec<String>,
    pub malware_families: Vec<String>,
    pub attack_ids: Vec<String>,
    pub references: Vec<String>,
    pub industries: Vec<String>,
    pub extract_source: Vec<String>,
    pub more_indicators: bool
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTXIndicator {
    pub id: u128,
    pub indicator: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub created: String,
    pub content: String,
    pub title: String,
    pub description: String,
    pub expiration: Option<String>,
    pub is_active: u8,
    pub role: Option<String>
}


/// Enriched Threat Record

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedThreatRecord {
    pub attack_types: Vec<AttackType>,
    pub attack_vectors: Vec<AttackVector>,
    pub urgency: (Urgency, Urgency),
    pub targets: Vec<Target>,
    pub locations: Vec<String>,
    pub expiration_date: String
}


/// Classification Functions

fn classify_attack_types(record: &OTXRecord) -> Vec<AttackType> {
    let mut a_types: Vec<AttackType> = vec![];
    let mut all_text = vec![
        record.name.as_str(),
        record.description.as_str(),
    ];
    all_text.extend(record.tags.iter().map(String::as_str));
    all_text.extend(record.indicators.iter().flat_map(|ind: &OTXIndicator| vec![
        ind.title.as_str(),
        ind.description.as_str(),
        ind.role.as_ref().map(String::as_str).unwrap_or("")
    ]));
    let flattened = all_text.join(" ").to_lowercase();

    for (keyword, a_type) in attack_type_keywords().iter() {
        if flattened.contains(keyword) && !a_types.contains(a_type) {
            a_types.push(*a_type);
        }
    }
    if a_types.is_empty() {
        vec![AttackType::Unknown]
    } else {
        a_types
    }
}

fn classify_attack_vectors(record: &OTXRecord) -> Vec<AttackVector> {
    let mut a_vectors: Vec<AttackVector> = vec![];
    let mut all_text = vec![
        record.name.as_str(),
        record.description.as_str(),
    ];
    all_text.extend(record.tags.iter().map(String::as_str));
    all_text.extend(record.indicators.iter().flat_map(|ind: &OTXIndicator| vec![
        ind.title.as_str(),
        ind.description.as_str(),
    ]));
    let flattened = all_text.join(" ").to_lowercase();

    for (keyword, a_vector) in attack_vector_keywords().iter() {
        if flattened.contains(keyword) && !a_vectors.contains(a_vector) {
            a_vectors.push(*a_vector);
        }
    }
    if a_vectors.is_empty() {
        vec![AttackVector::Unknown]
    } else {
        a_vectors
    }
}

fn classify_urgency(record: &OTXRecord) -> (Urgency, Urgency) {
    let mut urgency_info: (Urgency, Urgency) = (Urgency::Cold, Urgency::Low); 
    let mut all_text = vec![
        record.name.as_str(),
        record.description.as_str(),
    ];
    all_text.extend(record.tags.iter().map(String::as_str));
    let tipper: i32 = record.indicators.iter().map(|ind: &OTXIndicator| {
        if ind.is_active == 1 {
            1
        } else {
            -1
        }
    }).sum();
    let flattened = all_text.join(" ").to_lowercase();

    for (keyword, urgency_rec) in urgency_keywords().iter() {
        if flattened.contains(keyword) {
            match *urgency_rec {
                Urgency::Critical | Urgency::Medium | Urgency::Low => {
                    urgency_info.1 = *urgency_rec;
                }
                _ => {}
            }
        }
    }
    if tipper > 0 {
        urgency_info.0 = Urgency::Hot
    } else {
        urgency_info.0 = Urgency::Cold
    }
    urgency_info 
}

fn classify_targets(record: &OTXRecord) -> Vec<Target> {
    let mut targets: Vec<Target> = vec![];
    let mut all_text = vec![
        record.name.as_str(),
        record.description.as_str(),
    ];
    all_text.extend(record.tags.iter().map(String::as_str));
    all_text.extend(record.indicators.iter().flat_map(|ind: &OTXIndicator| vec![
        ind.title.as_str(),
        ind.description.as_str(),
    ]));
    let flattened = all_text.join(" ").to_lowercase();
    
    for (keyword, target) in target_keywords().iter() {
        if flattened.contains(keyword) && !targets.contains(target) {
            targets.push(*target);
        }
    }
    if targets.is_empty() {
        vec![Target::Unknown]
    } else {
        targets
    }
}

pub fn get_expiration(record: &OTXRecord) -> Option<String> {
    let mut t_exp_date: Option<std::time::SystemTime> = None;

    for indicator in &record.indicators {
        if let Some(expiration_str) = &indicator.expiration {
            if let Ok(expiration_date) = parse_iso8601(expiration_str) {
                
                if t_exp_date.is_none() || expiration_date > t_exp_date.unwrap() {
                    t_exp_date = Some(expiration_date);
                }
            }
        }
    }
    t_exp_date
        .map(|date| format_system_time(date))
}

fn parse_iso8601(date_str: &str) -> std::result::Result<std::time::SystemTime, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = date_str.split(['T', '-', ':', '.']).collect();
    if parts.len() < 6 {
        return Err("Invalid date format".into());
    }

    let year: u64 = parts[0].parse().map_err(|e| format!("Failed to parse year: {}", e))?;
    let month: u64 = parts[1].parse().map_err(|e| format!("Failed to parse month: {}", e))?;
    let day: u64 = parts[2].parse().map_err(|e| format!("Failed to parse day: {}", e))?;
    let hour: u64 = parts[3].parse().map_err(|e| format!("Failed to parse hour: {}", e))?;
    let minute: u64 = parts[4].parse().map_err(|e| format!("Failed to parse minute: {}", e))?;
    let second: u64 = parts[5].parse().map_err(|e| format!("Failed to parse second: {}", e))?;

    let duration_since_epoch = std::time::Duration::new(
        ((year - 1970) * 31_536_000)
            + ((month - 1) * 2_592_000)
            + ((day - 1) * 86_400) 
            + (hour * 3_600) 
            + (minute * 60) 
            + second,
        0,
    );

    Ok(std::time::SystemTime::UNIX_EPOCH + duration_since_epoch)
}

fn format_system_time(time: std::time::SystemTime) -> String {
    let duration_since_epoch = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration_since_epoch.as_secs();

    let year = 1970 + seconds / 31_536_000;
    let month = (seconds % 31_536_000) / 2_592_000 + 1;
    let day = (seconds % 2_592_000) / 86_400 + 1;
    let hour = (seconds % 86_400) / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        year, month, day, hour, minute, second
    )
}


/// Hashmap functions for synonymous cases

pub fn attack_type_keywords() -> HashMap<&'static str, AttackType> {
    let mut m = HashMap::new();

    m.insert("ransom", AttackType::Ransomware);
    m.insert("ransomware", AttackType::Ransomware);
    m.insert("locker", AttackType::Ransomware);
    m.insert("cryptolocker", AttackType::Ransomware);
    m.insert("encryptor", AttackType::Ransomware);
    m.insert("crypto-malware", AttackType::Ransomware);

    m.insert("malware", AttackType::Malware);
    m.insert("virus", AttackType::Malware);
    m.insert("worm", AttackType::Malware);
    m.insert("adware", AttackType::Malware);
    m.insert("rootkit", AttackType::Malware);
    m.insert("keylogger", AttackType::Malware);

    m.insert("ddos", AttackType::Ddos);
    m.insert("dos", AttackType::Ddos);
    m.insert("denial of service", AttackType::Ddos);
    m.insert("distributed denial of service", AttackType::Ddos);
    m.insert("flood attack", AttackType::Ddos);
    m.insert("syn flood", AttackType::Ddos);
    m.insert("amplification attack", AttackType::Ddos);

    m.insert("botnet", AttackType::Botnet);
    m.insert("bot network", AttackType::Botnet);
    m.insert("zombie network", AttackType::Botnet);
    m.insert("c&c", AttackType::Botnet);
    m.insert("command and control", AttackType::Botnet);

    m.insert("phish", AttackType::Phishing);
    m.insert("phishing", AttackType::Phishing);
    m.insert("spearphish", AttackType::Phishing);
    m.insert("spear-phishing", AttackType::Phishing);
    m.insert("whaling", AttackType::Phishing);
    m.insert("credential harvesting", AttackType::Phishing);
    m.insert("email scam", AttackType::Phishing);
    m.insert("smishing", AttackType::Phishing);
    m.insert("vishing", AttackType::Phishing);

    m.insert("trojan", AttackType::Trojan);
    m.insert("trojan horse", AttackType::Trojan);
    m.insert("dropper", AttackType::Trojan);
    m.insert("backdoor", AttackType::Trojan);
    m.insert("infostealer", AttackType::Trojan);

    m.insert("spyware", AttackType::Spyware);
    m.insert("snoopware", AttackType::Spyware);
    m.insert("tracking software", AttackType::Spyware);
    m.insert("monitoring tool", AttackType::Spyware);

    m.insert("brute force", AttackType::BruteForce);
    m.insert("bruteforce", AttackType::BruteForce);
    m.insert("credential stuffing", AttackType::BruteForce);
    m.insert("password cracking", AttackType::BruteForce);
    m.insert("dictionary attack", AttackType::BruteForce);

    m.insert("sql injection", AttackType::SQLInjection);
    m.insert("sqli", AttackType::SQLInjection);
    m.insert("injection attack", AttackType::SQLInjection);
    m.insert("database injection", AttackType::SQLInjection);
    m.insert("blind sql", AttackType::SQLInjection);
    m.insert("error-based injection", AttackType::SQLInjection);
    m.insert("union-based injection", AttackType::SQLInjection);

    m
}

pub fn attack_vector_keywords() -> HashMap<&'static str, AttackVector> {
    let mut m = HashMap::new();

    m.insert("email", AttackVector::Email);
    m.insert("phishing", AttackVector::Email);
    m.insert("spearphish", AttackVector::Email);
    m.insert("spoofing", AttackVector::Email);

    m.insert("web", AttackVector::WebApplication);
    m.insert("xss", AttackVector::WebApplication);
    m.insert("cross-site scripting", AttackVector::WebApplication);
    m.insert("sql injection", AttackVector::WebApplication);
    m.insert("sqli", AttackVector::WebApplication);
    m.insert("csrf", AttackVector::WebApplication);
    m.insert("directory traversal", AttackVector::WebApplication);

    m.insert("network", AttackVector::Network);
    m.insert("ddos", AttackVector::Network);
    m.insert("denial of service", AttackVector::Network);
    m.insert("port scan", AttackVector::Network);
    m.insert("mitm", AttackVector::Network);
    m.insert("man in the middle", AttackVector::Network);

    m.insert("cloud", AttackVector::CloudService);
    m.insert("aws", AttackVector::CloudService);
    m.insert("gcp", AttackVector::CloudService);
    m.insert("azure", AttackVector::CloudService);
    m.insert("bucket", AttackVector::CloudService);
    m.insert("s3", AttackVector::CloudService);
    m.insert("misconfig", AttackVector::CloudService);
    m.insert("storage exposure", AttackVector::CloudService);

    m.insert("supply chain", AttackVector::SupplyChain);
    m.insert("dependency confusion", AttackVector::SupplyChain);
    m.insert("software supply chain", AttackVector::SupplyChain);
    m.insert("package hijack", AttackVector::SupplyChain);
    m.insert("vendor compromise", AttackVector::SupplyChain);

    m
}

pub fn urgency_keywords() -> HashMap<&'static str, Urgency> {
    let mut m = HashMap::new();

    // Hot threats: immediate, active, breaking
    m.insert("hot", Urgency::Hot);
    m.insert("immediate", Urgency::Hot);
    m.insert("active", Urgency::Hot);
    m.insert("ongoing", Urgency::Hot);
    m.insert("breaking", Urgency::Hot);

    // Cold threats: old, inactive, stale
    m.insert("cold", Urgency::Cold);
    m.insert("stale", Urgency::Cold);
    m.insert("archived", Urgency::Cold);
    m.insert("historical", Urgency::Cold);
    m.insert("retired", Urgency::Cold);
    m.insert("inactive", Urgency::Cold);

    // Critical threats: high severity, urgent, severe
    m.insert("critical", Urgency::Critical);
    m.insert("high", Urgency::Critical);
    m.insert("severe", Urgency::Critical);
    m.insert("urgent", Urgency::Critical);
    m.insert("emergency", Urgency::Critical);

    // Medium threats
    m.insert("medium", Urgency::Medium);
    m.insert("moderate", Urgency::Medium);
    m.insert("average", Urgency::Medium);
    m.insert("balanced", Urgency::Medium);

    // Low threats: minor, low priority
    m.insert("low", Urgency::Low);
    m.insert("minor", Urgency::Low);
    m.insert("negligible", Urgency::Low);
    m.insert("low priority", Urgency::Low);
    m.insert("minimal", Urgency::Low);

    m
}

pub fn target_keywords() -> HashMap<&'static str, Target> {
    let mut m = HashMap::new();

    // Web Applications
    m.insert("webapp", Target::WebApp);
    m.insert("web app", Target::WebApp);
    m.insert("website", Target::WebApp);
    m.insert("web application", Target::WebApp);
    m.insert("web portal", Target::WebApp);
    m.insert("online service", Target::WebApp);
    m.insert("web service", Target::WebApp);

    // Infrastructure
    m.insert("infrastructure", Target::Infrastructure);
    m.insert("server", Target::Infrastructure);
    m.insert("servers", Target::Infrastructure);
    m.insert("datacenter", Target::Infrastructure);
    m.insert("data center", Target::Infrastructure);
    m.insert("network infra", Target::Infrastructure);
    m.insert("cloud infrastructure", Target::Infrastructure);
    m.insert("system", Target::Infrastructure);
    m.insert("backend", Target::Infrastructure);

    // API Abuse
    m.insert("api abuse", Target::ApiAbuse);
    m.insert("api exploitation", Target::ApiAbuse);
    m.insert("api attack", Target::ApiAbuse);
    m.insert("api misuse", Target::ApiAbuse);
    m.insert("rest api", Target::ApiAbuse);
    m.insert("graphql api", Target::ApiAbuse);
    m.insert("api endpoint", Target::ApiAbuse);

    // IoT Devices
    m.insert("iot", Target::IotDevices);
    m.insert("device", Target::IotDevices);
    m.insert("smart devices", Target::IotDevices);
    m.insert("smart home", Target::IotDevices);
    m.insert("embedded systems", Target::IotDevices);
    m.insert("industrial control systems", Target::IotDevices);
    m.insert("ics", Target::IotDevices);
    m.insert("plc", Target::IotDevices);
    m.insert("smart tv", Target::IotDevices);
    m.insert("iot network", Target::IotDevices);

    // User Focused
    m.insert("user", Target::UserFocused);
    m.insert("users", Target::UserFocused);
    m.insert("human", Target::UserFocused);
    m.insert("human target", Target::UserFocused);
    m.insert("social engineering", Target::UserFocused);
    m.insert("account takeover", Target::UserFocused);
    m.insert("identity theft", Target::UserFocused);
    m.insert("credential theft", Target::UserFocused);
    m.insert("login brute force", Target::UserFocused);
    m.insert("phishing scam", Target::UserFocused);

    // Email Attacks
    m.insert("email", Target::EmailAttack);
    m.insert("email attack", Target::EmailAttack);
    m.insert("email phishing", Target::EmailAttack);
    m.insert("email spoofing", Target::EmailAttack);
    m.insert("spam email", Target::EmailAttack);
    m.insert("malicious email", Target::EmailAttack);
    m.insert("email fraud", Target::EmailAttack);
    m.insert("spearphishing", Target::EmailAttack);
    m.insert("mail scam", Target::EmailAttack);
    m.insert("mail fraud", Target::EmailAttack);

    m
}