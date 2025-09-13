export const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS todos (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  bucket_id TEXT,
  alg TEXT NOT NULL,
  aad TEXT,
  nonce_b64 TEXT NOT NULL,
  cipher_b64 TEXT NOT NULL,
  kdf_salt_b64 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_todos_user_id ON todos(user_id);
`;

export const INSERT_SQL = `INSERT INTO todos (id, user_id, bucket_id, alg, aad, nonce_b64, cipher_b64, kdf_salt_b64, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

export const SELECT_BY_USER_SQL = `SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC`;
export const SELECT_BY_USER_AND_BUCKET_SQL = `SELECT * FROM todos WHERE user_id = ? AND bucket_id = ? ORDER BY created_at DESC`;

// Keep param length constant for hooks by always passing 2 params: [user_id, bucket_or_empty]
// If second param is empty string, this condition is a tautology: bucket_id = bucket_id
// If second param is a value, it filters: bucket_id = value
export const SELECT_BY_USER_OPTIONAL_BUCKET_SQL = `
SELECT * FROM todos
WHERE user_id = ?
  AND COALESCE(NULLIF(?, ''), bucket_id) = bucket_id
ORDER BY created_at DESC`;

export const UPDATE_SQL = `UPDATE todos SET alg = ?, aad = ?, nonce_b64 = ?, cipher_b64 = ?, kdf_salt_b64 = ?, updated_at = ? WHERE id = ? AND user_id = ?`;

export const DELETE_SQL = `DELETE FROM todos WHERE id = ? AND user_id = ?`;
