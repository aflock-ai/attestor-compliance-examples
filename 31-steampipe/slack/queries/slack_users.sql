/*
id: slack-member-posture
task: Slack workspace member posture — 2FA enrollment, privileged and guest accounts
plugin: slack
nist:
  - "3.5.3"
  - "3.1.1"
  - "3.1.2"
  - "3.1.5"
ksis:
  - KSI-IAM-MFA
severity: high
*/
-- `id as user_id` keeps the user identity axis distinct from slack_conversation's
-- `id` (see slack_channels.sql); the rookery `slack` convention maps user_id ->
-- slack:user: and team_id -> slack:team:. No display names / emails are selected.
select
  id as user_id,
  team_id,
  has_2fa,
  is_admin,
  is_owner,
  is_primary_owner,
  is_restricted,
  is_ultra_restricted,
  is_bot,
  deleted
from slack_user;
