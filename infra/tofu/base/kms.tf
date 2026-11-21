# One KMS key per environment (A0-10).
resource "aws_kms_key" "env" {
  description             = "Locksmith dev environment key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "env" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.env.key_id
}
