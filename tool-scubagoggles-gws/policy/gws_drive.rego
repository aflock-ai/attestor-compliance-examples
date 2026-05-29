# gws_drive.rego
#
# Google Workspace Drive & Docs policy — controls the external flow of content
# (and therefore CUI). Evaluates the raw config captured by the `scubagoggles`
# attestor (input.predicate.config) and emits deny[] for policyverify.
#
# Coverage rationale: these are the GWS controls a NIST 800-171 assessment draws
# on for Access Control — limiting CUI flow to authorized parties (3.1.3) and
# controlling publicly accessible content (3.1.22). The GWS↔800-171 mapping is
# the platform's job; this policy checks GWS controls and references their ids.
#
# Our rego, not CISA's; control intent informed by CISA's SCuBA Drive baseline
# (https://github.com/cisagov/ScubaGoggles, CC0-1.0).

package gws_drive

import future.keywords.contains
import future.keywords.if
import future.keywords.in

config := input.predicate.config

# GWS.DRIVEDOCS.1.1 — external sharing SHALL NOT be unrestricted. Acceptable
# modes restrict the audience (DISALLOWED, ALLOWLISTED_DOMAINS); "ALLOWED" lets
# users share with anyone, an uncontrolled path for CUI to leave the boundary.
deny contains msg if {
	some name, settings in config.policies
	settings.drive_and_docs_external_sharing.externalSharingMode == "ALLOWED"
	msg := sprintf("%q allows unrestricted external Drive sharing (externalSharingMode=ALLOWED) (GWS.DRIVEDOCS.1.1)", [name])
}

# GWS.DRIVEDOCS.4.1 — publishing files to the web SHALL be disabled (publicly
# accessible content must be controlled).
deny contains msg if {
	some name, settings in config.policies
	settings.drive_and_docs_external_sharing.allowPublishingFiles == true
	msg := sprintf("%q allows publishing Drive files to the web (GWS.DRIVEDOCS.4.1)", [name])
}
