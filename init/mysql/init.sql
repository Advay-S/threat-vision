CREATE TABLE enriched_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_types JSON,
    attack_vectors JSON,
    urgency JSON,
    targets JSON,
    locations JSON,
    expiration_date DATETIME
);