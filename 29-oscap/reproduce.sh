#!/bin/bash
# Reproduce the oscap attestor against real infrastructure.
# See README.md for the full scenario.
set -euo pipefail
oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_standard \
    --results oscap-results.xml \
    /usr/share/xml/scap/ssg/content/ssg-amzn2023-ds.xml
