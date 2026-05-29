# Unit tests for gws_commoncontrols.rego. Run with: opa test policy/
package gws_commoncontrols

import future.keywords.if
import future.keywords.in

# A fully compliant tenant: 2 super-admins, hardware-key 2SV, 12h session,
# enforcement on.
compliant := {"predicate": {"config": {
	"super_admins": [{"primaryEmail": "a@x"}, {"primaryEmail": "b@x"}],
	"policies": {"Root": {
		"security_two_step_verification_enforcement_factor": {"allowedSignInFactorSet": "ONLY_SECURITY_KEY"},
		"security_session_controls": {"webSessionDuration": "43200s"},
		"security_two_step_verification_enforcement": {"enforcedFrom": "2024-01-01T00:00:00Z"},
	}},
}}}

test_compliant_has_no_denials if {
	count(deny) == 0 with input as compliant
}

test_too_few_super_admins if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/super_admins", "value": [{"primaryEmail": "only@x"}]}])
	some msg in deny with input as cfg
	contains(msg, "below the required minimum of 2")
}

test_too_many_super_admins if {
	admins := [{"primaryEmail": sprintf("a%d@x", [i])} | some i in numbers.range(1, 9)]
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/super_admins", "value": admins}])
	some msg in deny with input as cfg
	contains(msg, "exceeds the maximum of 8")
}

test_weak_2sv_factor_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/security_two_step_verification_enforcement_factor/allowedSignInFactorSet", "value": "NO_TELEPHONY"}])
	some msg in deny with input as cfg
	contains(msg, "ONLY_SECURITY_KEY")
}

test_long_session_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/security_session_controls/webSessionDuration", "value": "72000s"}])
	some msg in deny with input as cfg
	contains(msg, "exceeds the 12h/43200s maximum")
}

test_unenforced_2sv_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/security_two_step_verification_enforcement/enforcedFrom", "value": ""}])
	some msg in deny with input as cfg
	contains(msg, "does not enforce 2-step verification")
}
