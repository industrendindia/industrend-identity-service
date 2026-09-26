ALTER TABLE industrendindia.customers
  ADD COLUMN IF NOT EXISTS login_pin_hash text,
  ADD COLUMN IF NOT EXISTS pin_failed_attempts smallint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS pin_locked_until timestamptz,
  ADD COLUMN IF NOT EXISTS pin_changed_at timestamptz;

CREATE INDEX IF NOT EXISTS customers_pin_lock_idx
  ON industrendindia.customers(pin_locked_until)
  WHERE pin_locked_until IS NOT NULL;

ALTER TABLE industrendindia.otp_challenges DROP CONSTRAINT IF EXISTS otp_challenges_purpose_check;
ALTER TABLE industrendindia.otp_challenges ADD CONSTRAINT otp_challenges_purpose_check CHECK(purpose IN('LOGIN','PIN_RESET','MOBILE_CHANGE','EMAIL_CHANGE'));
