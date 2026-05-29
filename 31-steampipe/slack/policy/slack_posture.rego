# slack_posture.rego
#
# TestifySec-authored Slack workspace security-posture policy. Evaluates the RAW
# rows captured by the rookery `steampipe` attestor running the Slack posture
# query pack (queries/slack_users.sql + slack_channels.sql) and emits deny[] for
# the policyverify rego engine.
#
# This is OUR rego, written against the steampipe attestor predicate and the
# policyverify deny[] contract. policyverify feeds input = the marshaled
# attestor, so the captured rows live at:
#
#     input.predicate.results[_].rows.rows[_]
#
# (each `steampipe query --output json` blob is stored as
# results[].rows = {"columns":[...],"rows":[...]}). A bare-array shape is also
# accepted for forward-compat.
#
# Control intent: treat the Slack workspace as if it carries (or may carry) CUI,
# so it must meet the NIST SP 800-171 Rev.2 requirements that map to a
# communications platform's identity and boundary posture. The precise
# control->requirement mapping is the platform's job; this policy checks Slack
# facts and cites the requirement ids it is informed by.

package slack_posture

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# --- evidence flattening ---------------------------------------------------

# Every captured row across all steampipe query results.
records contains r if {
	some i
	r := input.predicate.results[i].rows.rows[_]
}

# Forward-compat: accept a result whose `rows` is already a bare array.
records contains r if {
	some i
	res := input.predicate.results[i].rows
	is_array(res)
	r := res[_]
}

# Active human members: real people only (exclude bots, deactivated, Slackbot).
members contains u if {
	some u in records
	u.user_id
	not u.is_bot
	not u.deleted
	u.user_id != "USLACKBOT"
}

# Channels (non-archived). Present only when the capture token holds the channel
# scopes; absent on a least-privilege member-only token (the channel rule then
# simply finds nothing to flag).
channels contains c if {
	some c in records
	c.channel_id
	not c.is_archived
}

is_guest(u) if u.is_restricted == true
is_guest(u) if u.is_ultra_restricted == true

is_privileged(u) if u.is_admin == true
is_privileged(u) if u.is_owner == true
is_privileged(u) if u.is_primary_owner == true

# A member is treated as MFA-protected ONLY when has_2fa is explicitly boolean
# true. Everything else — false, the field absent, or null (Slack can return
# null for has_2fa when 2FA enrollment isn't readable) — counts as "not
# verified" and is flagged. Fail CLOSED on the highest-severity control: use
# `not has_mfa(u)` rather than `not u.has_2fa`, which would miss a null value.
has_mfa(u) if u.has_2fa == true

# --- controls --------------------------------------------------------------

# NIST SP 800-171 3.5.3 (IA-2) — use multifactor authentication. Every active
# member who could touch CUI must have 2FA enabled. Deny when any does not.
deny contains msg if {
	missing := {u.user_id | some u in members; not has_mfa(u)}
	count(missing) > 0
	msg := sprintf(
		"%d of %d active members have two-factor authentication DISABLED (NIST 800-171 3.5.3 / IA-2): %v",
		[count(missing), count(members), sort(missing)],
	)
}

# NIST SP 800-171 3.1.1 / 3.1.2 (AC-3) — limit access to authorized users.
# External guests (single/multi-channel) must not have standing access to a
# workspace carrying CUI. Deny per guest account.
deny contains msg if {
	some u in members
	is_guest(u)
	msg := sprintf(
		"guest account %q has workspace access; external/guest users must not reach a CUI boundary (NIST 800-171 3.1.1/3.1.2 / AC-3)",
		[u.user_id],
	)
}

# NIST SP 800-171 3.1.5 (AC-6) — least privilege. Flag when more than a quarter
# of members hold workspace admin/owner. The 25% ratio is a tunable policy
# choice — adjust `* 4` for your org's risk appetite.
deny contains msg if {
	count(members) > 0
	privileged := {u.user_id | some u in members; is_privileged(u)}
	count(privileged) * 4 > count(members)
	msg := sprintf(
		"%d of %d members hold workspace admin/owner privilege (>25%%); apply least privilege (NIST 800-171 3.1.5 / AC-6): %v",
		[count(privileged), count(members), sort(privileged)],
	)
}

# NIST SP 800-171 3.1.3 / 3.13.1 (AC-21 / SC-7) — control the flow of CUI and
# protect the boundary. Externally-shared (Slack Connect) channels carry data to
# organizations outside the boundary. Deny per externally-shared channel.
deny contains msg if {
	some c in channels
	c.is_ext_shared == true
	msg := sprintf(
		"channel %q (id %s) is shared externally via Slack Connect; CUI flow across the boundary must be controlled (NIST 800-171 3.1.3/3.13.1 / AC-21/SC-7)",
		[c.name, c.channel_id],
	)
}
