SET search_path TO industrendindia,pg_catalog;

CREATE TABLE admin_users (
  admin_user_id uuid PRIMARY KEY,
  email varchar(254) NOT NULL,
  display_name varchar(140) NOT NULL,
  password_hash text NOT NULL,
  status varchar(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','LOCKED','DISABLED')),
  mfa_required boolean NOT NULL DEFAULT true,
  failed_attempts smallint NOT NULL DEFAULT 0,
  locked_until timestamptz,
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX admin_users_email_uq ON admin_users(lower(email));
CREATE INDEX admin_users_lock_idx ON admin_users(locked_until) WHERE locked_until IS NOT NULL;

CREATE TABLE admin_roles (
  role_key varchar(50) PRIMARY KEY,
  description varchar(240) NOT NULL
);
INSERT INTO admin_roles(role_key,description) VALUES
  ('MARKETPLACE_ADMIN','Full marketplace administration'),
  ('QUOTATION_MANAGER','Review enquiries and publish customer quotations')
ON CONFLICT(role_key) DO NOTHING;

CREATE TABLE admin_user_roles (
  admin_user_id uuid NOT NULL REFERENCES admin_users(admin_user_id) ON DELETE CASCADE,
  role_key varchar(50) NOT NULL REFERENCES admin_roles(role_key) ON DELETE RESTRICT,
  PRIMARY KEY(admin_user_id,role_key)
);

CREATE TABLE admin_sessions (
  session_id uuid PRIMARY KEY,
  admin_user_id uuid NOT NULL REFERENCES admin_users(admin_user_id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,
  csrf_hash char(64) NOT NULL,
  user_agent_hash char(64),
  ip_created inet,
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX admin_sessions_user_idx ON admin_sessions(admin_user_id,expires_at DESC);
CREATE INDEX admin_sessions_active_idx ON admin_sessions(token_hash,expires_at) WHERE revoked_at IS NULL;

