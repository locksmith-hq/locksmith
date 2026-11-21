locals {
  ecr_repos = toset(["locksmith-control-plane", "locksmith-gateway"])
}

resource "aws_ecr_repository" "this" {
  for_each             = local.ecr_repos
  name                 = each.key
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.env.arn
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = local.ecr_repos
  repository = aws_ecr_repository.this[each.key].name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the 5 newest images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 5 }
      action       = { type = "expire" }
    }]
  })
}
