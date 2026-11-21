# Checkpoints: Object Lock in governance mode (A0-11). Artifacts: plain, versionless.
resource "aws_s3_bucket" "checkpoints" {
  bucket              = "${var.name}-checkpoints-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.checkpoint_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.checkpoints]
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.name}-artifacts-${data.aws_caller_identity.current.account_id}"
}

locals {
  buckets = {
    checkpoints = aws_s3_bucket.checkpoints.id
    artifacts   = aws_s3_bucket.artifacts.id
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.buckets
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.env.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = local.buckets
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Keep artifact storage from growing silently.
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire-30d"
    status = "Enabled"
    filter {}
    expiration {
      days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
