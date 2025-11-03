-- Minimal schema for MysqlStorage
CREATE TABLE csrf_cache (
  token_hash VARCHAR(64) PRIMARY KEY,
  payload    JSON NOT NULL,
  created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;