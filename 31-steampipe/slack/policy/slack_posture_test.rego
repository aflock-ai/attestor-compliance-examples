package slack_posture

import future.keywords.if
import future.keywords.in

# mk wraps query rows in the policyverify input shape:
# input.predicate.results[_].rows.rows[_]. results may carry several query
# outputs; here we use one entry for members and (optionally) one for channels.
mk(memberRows) := {"predicate": {"results": [{"rows": {"rows": memberRows}}]}}

mk2(memberRows, channelRows) := {"predicate": {"results": [
	{"rows": {"rows": memberRows}},
	{"rows": {"rows": channelRows}},
]}}

has_msg(d, needle) if {
	some msg in d
	contains(msg, needle)
}

# --- MFA (3.5.3 / IA-2) ----------------------------------------------------

test_mfa_denied_when_a_member_lacks_2fa if {
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U2", "has_2fa": false, "is_bot": false, "deleted": false},
	])
	has_msg(d, "two-factor authentication DISABLED")
}

test_mfa_clean_when_all_members_have_2fa if {
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U2", "has_2fa": true, "is_bot": false, "deleted": false},
	])
	not has_msg(d, "two-factor authentication DISABLED")
}

# Fail CLOSED: has_2fa null (Slack can return this) or absent must be flagged,
# not treated as compliant. Guards the has_mfa helper against the `not u.has_2fa`
# fail-open.
test_mfa_denied_when_has_2fa_is_null if {
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": null, "is_bot": false, "deleted": false},
	])
	has_msg(d, "two-factor authentication DISABLED")
}

test_mfa_denied_when_has_2fa_absent if {
	d := deny with input as mk([
		{"user_id": "U1", "is_bot": false, "deleted": false},
	])
	has_msg(d, "two-factor authentication DISABLED")
}

test_bots_deleted_and_slackbot_are_not_members if {
	# A bot, a deactivated user, and Slackbot all lack 2FA but must NOT count.
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "B1", "has_2fa": false, "is_bot": true, "deleted": false},
		{"user_id": "D1", "has_2fa": false, "is_bot": false, "deleted": true},
		{"user_id": "USLACKBOT", "has_2fa": false, "is_bot": false, "deleted": false},
	])
	not has_msg(d, "two-factor authentication DISABLED")
}

# --- Guests (3.1.1 / 3.1.2 / AC-3) -----------------------------------------

test_guest_account_denied if {
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "G1", "has_2fa": true, "is_bot": false, "deleted": false, "is_restricted": true},
	])
	has_msg(d, "guest account")
}

test_ultra_restricted_guest_denied if {
	d := deny with input as mk([
		{"user_id": "G2", "has_2fa": true, "is_bot": false, "deleted": false, "is_ultra_restricted": true},
	])
	has_msg(d, "guest account")
}

# --- Least privilege (3.1.5 / AC-6) ----------------------------------------

test_excessive_admins_denied if {
	# 2 of 4 members are admin/owner = 50% > 25%.
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false, "is_owner": true},
		{"user_id": "U2", "has_2fa": true, "is_bot": false, "deleted": false, "is_admin": true},
		{"user_id": "U3", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U4", "has_2fa": true, "is_bot": false, "deleted": false},
	])
	has_msg(d, "least privilege")
}

test_reasonable_admin_ratio_not_denied if {
	# 1 of 8 = 12.5% <= 25%.
	d := deny with input as mk([
		{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false, "is_owner": true},
		{"user_id": "U2", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U3", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U4", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U5", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U6", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U7", "has_2fa": true, "is_bot": false, "deleted": false},
		{"user_id": "U8", "has_2fa": true, "is_bot": false, "deleted": false},
	])
	not has_msg(d, "least privilege")
}

# --- External channels (3.1.3 / 3.13.1 / AC-21 / SC-7) ---------------------

test_external_shared_channel_denied if {
	d := deny with input as mk2(
		[{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false}],
		[{"channel_id": "C1", "name": "partner-x", "is_ext_shared": true, "is_archived": false}],
	)
	has_msg(d, "shared externally via Slack Connect")
}

test_internal_channel_not_denied if {
	d := deny with input as mk2(
		[{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false}],
		[{"channel_id": "C1", "name": "general", "is_ext_shared": false, "is_archived": false}],
	)
	not has_msg(d, "shared externally via Slack Connect")
}

# --- Fully compliant workspace ---------------------------------------------

test_compliant_workspace_has_no_denials if {
	d := deny with input as mk2(
		[
			{"user_id": "U1", "has_2fa": true, "is_bot": false, "deleted": false, "is_owner": true},
			{"user_id": "U2", "has_2fa": true, "is_bot": false, "deleted": false},
			{"user_id": "U3", "has_2fa": true, "is_bot": false, "deleted": false},
			{"user_id": "U4", "has_2fa": true, "is_bot": false, "deleted": false},
		],
		[{"channel_id": "C1", "name": "general", "is_ext_shared": false, "is_archived": false}],
	)
	count(d) == 0
}
