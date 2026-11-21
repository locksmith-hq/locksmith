# Aurora Serverless v2 PostgreSQL, min 0 ACU with auto-pause (A0-1, A0-8).
resource "aws_db_subnet_group" "aurora" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

# Reachable only from the session tasks' security group.
resource "aws_security_group" "aurora" {
  name        = "${var.name}-aurora"
  description = "Aurora, open only to session tasks"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${var.name}-aurora" }
}

resource "aws_vpc_security_group_ingress_rule" "aurora_from_session" {
  security_group_id            = aws_security_group.aurora.id
  referenced_security_group_id = aws_security_group.session_tasks.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "PostgreSQL from session tasks only"
}

resource "aws_rds_cluster" "main" {
  cluster_identifier = var.name
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = var.aurora_engine_version
  database_name      = "locksmith"
  master_username    = "locksmith_admin"
  # Apps and operators use IAM database auth. AWS requires a master password at
  # create time, and OpenTofu 1.10 has no write-only/ephemeral values, so the
  # cluster is created with a public, non-secret bootstrap value that the
  # provisioner below replaces with a random password nobody keeps, before any
  # instance exists. No usable password reaches code, state, plan or outputs.
  # No RDS-managed Secrets Manager secret either (A0-16): manage_master_user_password
  # stays off, and the plan policy rejects it.
  master_password = "bootstrap-replaced-at-create"

  db_subnet_group_name   = aws_db_subnet_group.aurora.name
  vpc_security_group_ids = [aws_security_group.aurora.id]
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.env.arn

  iam_database_authentication_enabled = true
  backup_retention_period             = 1
  skip_final_snapshot                 = true
  deletion_protection                 = false
  apply_immediately                   = true

  serverlessv2_scaling_configuration {
    min_capacity             = 0
    max_capacity             = var.aurora_max_acu
    seconds_until_auto_pause = var.aurora_seconds_until_auto_pause
  }

  lifecycle {
    # The real password is set out of band below and is never read back.
    ignore_changes = [master_password]
  }

  # Runs once, on create, on the machine that applies (needs the aws CLI).
  # The random password exists only in a 0600 temp file for one API call and is
  # never printed, logged or stored. Break-glass: an operator resets it with
  # `aws rds modify-db-cluster --master-user-password` and discards it after use.
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    environment = {
      CLUSTER    = self.cluster_identifier
      AWS_REGION = var.region
    }
    command = <<-EOT
      set -euo pipefail
      umask 077
      f="$(mktemp)"
      trap 'rm -f "$f"' EXIT
      pw="$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
      printf '{"DBClusterIdentifier":"%s","MasterUserPassword":"%s","ApplyImmediately":true}' "$CLUSTER" "$${pw:0:40}" >"$f"
      unset pw
      aws rds modify-db-cluster --cli-input-json "file://$f" >/dev/null
      aws rds wait db-cluster-available --db-cluster-identifier "$CLUSTER"
    EOT
  }
}

resource "aws_rds_cluster_instance" "main" {
  identifier          = "${var.name}-1"
  cluster_identifier  = aws_rds_cluster.main.id
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  instance_class      = "db.serverless"
  publicly_accessible = false
}
