#!/bin/bash
# Simulate trivy producing SARIF output
cat > trivy-results.sarif << 'SARIF'
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "version": "0.69.3",
          "informationUri": "https://github.com/aquasecurity/trivy"
        }
      },
      "results": [
        {
          "ruleId": "CVE-2024-21626",
          "level": "error",
          "message": {
            "text": "runc: file descriptor leak vulnerability in container runtime"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "Dockerfile"
                }
              }
            }
          ]
        },
        {
          "ruleId": "CVE-2023-44487",
          "level": "warning",
          "message": {
            "text": "HTTP/2 Rapid Reset attack vulnerability in golang.org/x/net"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "go.sum"
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
SARIF
echo "Trivy scan complete. SARIF report written."
