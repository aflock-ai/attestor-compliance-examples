# 25 — `aws` ✅ validated against real infrastructure

Real AWS Instance Identity Document (IID) from a t3.small EC2 instance running in us-east-1f. The attestor fetches the IID from the EC2 metadata service (IMDSv2) and verifies the signature against the AWS-published us-east-1 public certificate.

## Predicate excerpt

```json
{
  "devpayProductCodes": null,
  "marketplaceProductCodes": null,
  "availabilityZone": "us-east-1f",
  "privateIp": "REDACTED.private.ip",
  "version": "2017-09-30",
  "region": "us-east-1",
  "instanceId": "i-0a112150767ab72cf",
  "billingProducts": null,
  "instanceType": "t3.small",
  "accountId": "898769392027",
  "pendingTime": "2026-05-22T12:28:56Z",
  "imageId": "ami-02b2c1b57c5105166",
  "kernelId": "",
  "ramdiskId": "",
  "architecture": "x86_64",
  "rawiid": "{\n  \"accountId\" : \"898769392027\",\n  \"architecture\" : \"x86_64\",\n  \"availabilityZone\" : \"us-east-1f\",\n  \"billingProducts\" : null,\n  \"devpayProductCodes\" : null,\n  \"marketplaceProductCodes\" : null,\n  \"imageId\" : \"ami-02b2c1b57c5105166\",\n  \"instanceId\" : \"i-0a112150767ab72cf\",\n  \"instanceType\" : \"t3.small\",\n  \"kernelId\" : null,\n  \"pendingTime\" : \"2026-05-22T12:28:56Z\",\n  \"privateIp\" : \"REDACTED.private.ip\",\n  \"ramdiskId\" : null,\n  \"region\" : \"us-east-1\",\n  \"version\" : \"2017-09-30\"\n}",
  "rawsig": "Ktk7Sumj0CerMVreR9KKTZtsq+sXSzLvcZ8m7qUQa8WniDSX4DsIK4hkrgwln+0rDKsmtZGhXBM+\nuCmOEJXfG/qiGyUGrAulOpUN+4nAF3RCBxbSx9H2y70Vga+pPczZc3zmh02WXk6AoRHOhepeJ+QL\nzu0uMsX+lN0MhOlL/4E=",
  "publickey": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHvRjf/0kStpJ248khtIaN8qkD\nN3tkw4VjvA9nvPl2anJO+eIBUqPfQG09kZlwpWpmyO8bGB2RWqWxCwuB/dcnIob6\nw420k9WY5C0IIGtDRNauN3kuvGXkw3HEnF0EjYr0pcyWUvByWY4KswZV42X7Y7XS\nS13hOIcL6NLA+H94/QIDAQAB\n-----END PUBLIC KEY-----\n"
}
```

## What we found

Real instance i-0a112150767ab72cf in account 898769392027. Real AWS-signed RSA signature over the IID. Exposed a bug: the attestor setter for `--attestor-aws-region-cert` rejects empty default values, making the attestor un-instantiable without the flag even though built-in certs exist for major regions. Filed.

## Reproduce

```bash
cilock run --step ec2-identity \
  --signer-file-key-path key.pem --outfile aws-iid.json --workingdir . \
  --attestations aws \
  --attestor-aws-region-cert /opt/cilock/aws-us-east-1.pem \
  -- echo "captured EC2 instance identity"
```
