# Unit tests for gws_drive.rego. Run with: opa test policy/
package gws_drive

import future.keywords.if
import future.keywords.in

compliant := {"predicate": {"config": {"policies": {"Root": {"drive_and_docs_external_sharing": {
	"externalSharingMode": "DISALLOWED",
	"allowPublishingFiles": false,
}}}}}}

test_compliant_has_no_denials if {
	count(deny) == 0 with input as compliant
}

test_unrestricted_sharing_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/drive_and_docs_external_sharing/externalSharingMode", "value": "ALLOWED"}])
	some m in deny with input as cfg
	contains(m, "unrestricted external")
}

test_web_publishing_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/drive_and_docs_external_sharing/allowPublishingFiles", "value": true}])
	some m in deny with input as cfg
	contains(m, "publishing")
}

test_allowlisted_domains_ok if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/drive_and_docs_external_sharing/externalSharingMode", "value": "ALLOWLISTED_DOMAINS"}])
	count(deny) == 0 with input as cfg
}
