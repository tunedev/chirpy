-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
  gen_random_uuid(),
  NOW(), NOW(),
  $1, $2
)
RETURNING *;

-- name: DevAdminDBReset :exec
DELETE FROM users where 1=1; 

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1
LIMIT 1;

-- name: UpdateUser :one
UPDATE users
SET hashed_password = $2,
    email = COALESCE($3, email)
WHERE id = $1
RETURNING *;

-- name: UpgradeUser :exec
Update users
SET is_chirpy_red = TRUE
WHERE id = $1;
