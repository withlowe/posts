-- Posts — items. One row per arrival, whatever the source.
CREATE TABLE IF NOT EXISTS items (
  id        TEXT PRIMARY KEY,
  feed      TEXT NOT NULL,
  hook      TEXT NOT NULL DEFAULT '',
  created   TEXT NOT NULL,
  sender    TEXT NOT NULL DEFAULT '',
  subject   TEXT NOT NULL DEFAULT '',
  body      TEXT NOT NULL DEFAULT '',
  enc       INTEGER NOT NULL DEFAULT 0,
  event_id  TEXT NOT NULL,
  flags     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX  IF NOT EXISTS items_feed    ON items (feed, created DESC);
CREATE UNIQUE INDEX IF NOT EXISTS items_event ON items (event_id);

-- Encrypted attachment bytes. Ciphertext only: the file key lives inside the
-- sealed message, so this table is readable without being useful.
CREATE TABLE IF NOT EXISTS blobs (
  id      TEXT PRIMARY KEY,
  created TEXT NOT NULL,
  bytes   INTEGER NOT NULL,
  data    TEXT NOT NULL
);
