-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens(token, updated_at, user_id, expires_at)
VALUES(
  $1, 
  NOW(), $2, $3
)
RETURNING *;

-- name: RevokeUsersPrevRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE user_id = $1;

-- name: GetUserFromRefreshToken :one
SELECT * FROM refresh_tokens
JOIN users ON users.id = user_id
WHERE token = $1
  AND expires_at > NOW();

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
  updated_at = NOW()
WHERE token = $1;
