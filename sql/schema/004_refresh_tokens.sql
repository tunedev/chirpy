-- +goose Up
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL,
  user_id UUID NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP DEFAULT NULL,
  CONSTRAINT fk_refreshtoken_user
    FOREIGN KEY (user_id)
    REFERENCES users (id)
    ON DELETE CASCADE
);

-- +goose Down
DROP TABLE refresh_tokens;