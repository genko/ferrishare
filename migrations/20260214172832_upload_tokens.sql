CREATE TABLE IF NOT EXISTS upload_tokens
(
  id INTEGER PRIMARY KEY NOT NULL,
  token_sha256sum TEXT NOT NULL UNIQUE,
  created_ts TEXT NOT NULL,
  used_ts TEXT,
  used_by_ip TEXT
) STRICT;
