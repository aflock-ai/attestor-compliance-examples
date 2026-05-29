# Unit tests for gws_gmail.rego. Run with: opa test policy/
package gws_gmail

import future.keywords.if
import future.keywords.in

compliant := {"predicate": {"config": {
	"dmarc_records": [{"domain": "x.com", "rdata": ["v=DMARC1;p=reject;pct=100"]}],
	"dkim_records": [{"domain": "x.com", "rdata": ["v=DKIM1; k=rsa; p=ABC"]}],
	"spf_records": [{"domain": "x.com", "rdata": ["v=spf1 include:_spf.google.com -all"]}],
	"policies": {"Root": {"gmail_email_attachment_safety": {"enableAnomalousAttachmentProtection": true}}},
}}}

test_compliant_has_no_denials if {
	count(deny) == 0 with input as compliant
}

test_dmarc_p_none_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/dmarc_records/0/rdata", "value": ["v=DMARC1;p=none;"]}])
	some m in deny with input as cfg
	contains(m, "DMARC")
}

test_dkim_absent_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/dkim_records/0/rdata", "value": []}])
	some m in deny with input as cfg
	contains(m, "DKIM")
}

test_spf_absent_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/spf_records/0/rdata", "value": []}])
	some m in deny with input as cfg
	contains(m, "SPF")
}

test_anomalous_attachment_off_denied if {
	cfg := json.patch(compliant, [{"op": "replace", "path": "/predicate/config/policies/Root/gmail_email_attachment_safety/enableAnomalousAttachmentProtection", "value": false}])
	some m in deny with input as cfg
	contains(m, "anomalous")
}
