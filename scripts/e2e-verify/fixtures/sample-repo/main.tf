# A minimal S3 bucket resource missing a lifecycle configuration —
# CKV2_AWS_61, the same real check tests/unit/fixtures/checkov/one_finding.json
# already captures against a real checkov 3.3.19 binary.
resource "aws_s3_bucket" "logs" {
  bucket = "example-logs-bucket"
}
