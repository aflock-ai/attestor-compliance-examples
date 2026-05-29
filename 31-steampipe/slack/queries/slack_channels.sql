/*
id: slack-channel-posture
task: Slack channel posture — external (Slack Connect) sharing across the boundary
plugin: slack
nist:
  - "3.1.3"
  - "3.13.1"
ksis:
  - KSI-CNA-NTW
severity: medium
*/
-- `id as channel_id` keeps the channel identity axis distinct from slack_user's
-- `id`; the rookery `slack` convention maps channel_id -> slack:channel:.
select
  id as channel_id,
  name,
  is_private,
  is_archived,
  is_general,
  is_ext_shared,
  is_shared,
  is_org_shared,
  is_pending_ext_shared,
  num_members
from slack_conversation;
