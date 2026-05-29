# gws_commoncontrols.rego
#
# TestifySec-authored Google Workspace "Common Controls" policy. Evaluates the
# RAW provider configuration captured by the `scubagoggles` attestor
# (input.predicate.config) and emits deny[] for the policyverify rego engine.
#
# This is OUR rego, written against the scubagoggles attestor predicate and the
# policyverify deny[] contract — NOT a copy of CISA's. The control intent is
# informed by CISA's SCuBA GWS Common Controls baseline
# (https://github.com/cisagov/ScubaGoggles, CC0-1.0); the rego is original.
#
# Why our own rego: CISA's baselines read input.policies at the top level and
# emit a `tests` set; policyverify feeds input.predicate.config and queries
# <package>.deny on every module, so consuming CISA's rego unchanged would mean
# forking it (input-path rewrite + per-module deny rules). Purpose-built deny
# rules over our predicate sidestep that and keep the verdict in our trust
# domain.

package gws_commoncontrols

import future.keywords.contains
import future.keywords.if
import future.keywords.in

config := input.predicate.config

# Container (OU/group) settings maps, e.g. config.policies["TestifySec, Inc."].
containers := config.policies

# GWS.COMMONCONTROLS.6.2 — a minimum of 2 and a maximum of 8 distinct
# super-admins SHALL be configured.
deny contains msg if {
	n := count(config.super_admins)
	n < 2
	msg := sprintf("super-admin count %d is below the required minimum of 2 (GWS.COMMONCONTROLS.6.2)", [n])
}

deny contains msg if {
	n := count(config.super_admins)
	n > 8
	msg := sprintf("super-admin count %d exceeds the maximum of 8 (GWS.COMMONCONTROLS.6.2)", [n])
}

# GWS.COMMONCONTROLS.1.1 — phishing-resistant MFA: the allowed 2SV sign-in
# factor set SHALL be hardware security keys only (ONLY_SECURITY_KEY).
deny contains msg if {
	some name, settings in containers
	factor := settings.security_two_step_verification_enforcement_factor.allowedSignInFactorSet
	factor != "ONLY_SECURITY_KEY"
	msg := sprintf("%q allows non-phishing-resistant 2SV factor %q; require ONLY_SECURITY_KEY (GWS.COMMONCONTROLS.1.1)", [name, factor])
}

# GWS.COMMONCONTROLS.4.1 — users SHALL be forced to re-authenticate after a
# web session no longer than 12 hours (43200 seconds).
deny contains msg if {
	some name, settings in containers
	dur := settings.security_session_controls.webSessionDuration
	seconds := to_number(trim_suffix(dur, "s"))
	seconds > 43200
	msg := sprintf("%q web-session duration %s exceeds the 12h/43200s maximum (GWS.COMMONCONTROLS.4.1)", [name, dur])
}

# GWS.COMMONCONTROLS.1.x — 2-step verification SHALL be enforced. Deny any
# container that exposes the enforcement setting but leaves enforcedFrom unset.
deny contains msg if {
	some name, settings in containers
	enforcement := settings.security_two_step_verification_enforcement
	enforcement.enforcedFrom == ""
	msg := sprintf("%q does not enforce 2-step verification (enforcedFrom is empty) (GWS.COMMONCONTROLS.1)", [name])
}
