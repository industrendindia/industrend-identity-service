alter table industrendindia.otp_challenges
  drop constraint if exists otp_challenges_purpose_check;

alter table industrendindia.otp_challenges
  add constraint otp_challenges_purpose_check
  check (purpose in ('LOGIN','PIN_RESET','MOBILE_CHANGE','EMAIL_CHANGE','SELLER_ONBOARDING'));
