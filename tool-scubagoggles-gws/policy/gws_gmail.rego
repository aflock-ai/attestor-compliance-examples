# gws_gmail.rego
#
# Google Workspace Gmail policy — email-transmission integrity and anti-spoofing
# checks (DMARC / SPF / DKIM) plus attachment protection. Evaluates the raw
# config captured by the `scubagoggles` attestor (input.predicate.config) and
# emits deny[] for policyverify.
#
# Coverage rationale: these are the GWS controls a NIST 800-171 assessment draws
# on for the System & Communications Protection (3.13) and System & Information
# Integrity families — protecting the integrity/authenticity of CUI in transit.
# The GWS↔800-171 mapping itself is the platform's job; this policy only checks
# GWS controls and references their GWS ids.
#
# Our rego, not CISA's; control intent informed by CISA's SCuBA Gmail baseline
# (https://github.com/cisagov/ScubaGoggles, CC0-1.0).

package gws_gmail

import future.keywords.contains
import future.keywords.if
import future.keywords.in

config := input.predicate.config

# Normalize one DNS rdata string for substring checks.
norm(r) := replace(lower(r), " ", "")

# GWS.GMAIL.7 — DMARC SHALL enforce: policy must be reject or quarantine, not
# none. A published-but-p=none record monitors only and does not stop spoofing.
dmarc_enforced(rec) if {
	some r in rec.rdata
	contains(norm(r), "p=reject")
}

dmarc_enforced(rec) if {
	some r in rec.rdata
	contains(norm(r), "p=quarantine")
}

deny contains msg if {
	some rec in config.dmarc_records
	not dmarc_enforced(rec)
	msg := sprintf("DMARC for %q does not enforce (p must be reject or quarantine) (GWS.GMAIL.7)", [rec.domain])
}

# GWS.GMAIL.3.1 — DKIM SHALL be enabled (a non-empty DKIM record published).
deny contains msg if {
	some rec in config.dkim_records
	count([r | some r in rec.rdata; r != ""]) == 0
	msg := sprintf("no DKIM record published for %q (GWS.GMAIL.3.1)", [rec.domain])
}

# GWS.GMAIL.4.1 — an SPF policy SHALL be published.
deny contains msg if {
	some rec in config.spf_records
	count([r | some r in rec.rdata; startswith(norm(r), "v=spf1")]) == 0
	msg := sprintf("no SPF record published for %q (GWS.GMAIL.4.1)", [rec.domain])
}

# GWS.GMAIL.5 — anomalous-attachment protection SHALL be enabled.
deny contains msg if {
	some name, settings in config.policies
	settings.gmail_email_attachment_safety.enableAnomalousAttachmentProtection == false
	msg := sprintf("%q has anomalous-attachment protection disabled (GWS.GMAIL.5)", [name])
}
