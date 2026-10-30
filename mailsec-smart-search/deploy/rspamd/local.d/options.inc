filters = "chartable,regexp";
task_timeout = 5s;
max_message = 15M;
disable_monitoring = true;
dns { nameserver = ["127.0.0.1:1"]; timeout = 0.1s; retransmits = 0; }
