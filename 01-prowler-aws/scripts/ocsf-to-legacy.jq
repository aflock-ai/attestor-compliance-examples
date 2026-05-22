[ .[] | {
  CheckID: (.finding.uid | sub("^prowler-aws-"; "") | split("-")[0]),
  CheckTitle: .finding.title,
  Provider: "aws",
  Status: (if .status == "Success" then "PASS" else "FAIL" end),
  Severity: .severity,
  Region: (.cloud.region // (.resources[0]?.region // "")),
  ServiceName: (.resources[0]?.group.name // ""),
  ResourceId: (.resources[0]?.name // ""),
  ResourceArn: (.resources[0]?.uid // ""),
  AccountId: .cloud.account.uid,
  StatusExtended: (.status_detail // .message)
} ]
