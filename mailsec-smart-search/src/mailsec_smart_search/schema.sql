-- mail_id is a deterministic digest of the raw EML. Hash partitioning keeps every
-- replay of the same message in one partition, where ReplacingMergeTree can merge it.
CREATE TABLE IF NOT EXISTS {database}.mail_records
(
    mail_id String,
    raw_sha256 String,
    raw_path String,
    source LowCardinality(String),
    ingested_at DateTime64(3, 'UTC'),
    sent_at Nullable(DateTime64(3, 'UTC')),
    header_message_id String,
    sender String,
    sender_domain String,
    recipients Array(String),
    subject String,
    body_text String,
    headers_json String,
    attachments_json String,
    attachment_count UInt16,
    attachment_suffixes Array(String),
    urls Array(String),
    claimed_spf String,
    parse_status LowCardinality(String),
    parse_errors Array(String),
    truncated Bool,
    parser_version String,
    INDEX idx_sent_at sent_at TYPE minmax GRANULARITY 1,
    INDEX idx_sender_domain sender_domain TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree
PARTITION BY cityHash64(mail_id) % 16
ORDER BY mail_id;

-- Detection outputs are evidence, not mutable columns on a mail row. Preserve each
-- independent model/rule/AV result and fusion revision as an append-only event.
CREATE TABLE IF NOT EXISTS {database}.analysis_events
(
    event_id UUID,
    mail_id String,
    created_at DateTime64(3, 'UTC'),
    analysis_json String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(created_at)
ORDER BY (mail_id, created_at, event_id);
