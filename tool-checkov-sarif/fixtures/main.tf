// Intentionally insecure Terraform fixture used to give Checkov real findings
// for the attestation walkthrough. Do not deploy. The misconfigurations below
// are well-known Checkov checks (CKV_AWS_*).

resource "aws_s3_bucket" "demo" {
  bucket = "rookery-checkov-demo"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "open-ssh"
  description = "Intentionally open SSH for demo"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
