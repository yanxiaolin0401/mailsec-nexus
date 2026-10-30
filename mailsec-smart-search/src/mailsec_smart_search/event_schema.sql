-- Independent normalized JSON events. Legacy mail_records is not modified.
CREATE TABLE IF NOT EXISTS {database}.mail_events
(
    event_id String,
    event_time DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC'),
    source_type LowCardinality(String),
    source_system_id LowCardinality(String),
    source_event_id String,
    trace_id String,
    payload_hash String,
    mail_hash String,
    sender_account String,
    receiver_accounts Array(String),
    subject String,
    sender_ip String,
    ingress_ip String,
    sender_country LowCardinality(String),
    sender_isp LowCardinality(String),
    risk_verdict LowCardinality(String),
    risk_level LowCardinality(String),
    risk_score UInt8,
    feature_tags Array(String),
    data_quality_tags Array(String),
    sender_host String,
    suspicious_string String,
    malicious_sender_ip String,
    tenant_email_addr_url String,
    external_urls Array(String),
    external_attachments Array(Map(String, String)),
    mail_headers String,
    mail_date DateTime64(3, 'UTC'),
    reply_to String,
    src_email_address String,
    to_email_address String,
    raw_json String,
    text_content String,
    INDEX idx_sender_account sender_account TYPE bloom_filter GRANULARITY 4,
    INDEX idx_event_time event_time TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY cityHash64(event_id) % 16
ORDER BY event_id;
