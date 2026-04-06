provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAI44QH8DHBEXAMP06"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE0006"
}

resource "aws_db_instance" "production" {
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r6g.xlarge"
  username       = "dbadmin"
  password       = "T3rr@f0rm_Pr0d_DBpa$$"
  port           = 5432
}

resource "aws_secretsmanager_secret_version" "api_key" {
  secret_string = "sk_live_TerraformSecretKeyValue01"
}

# Non-secrets: resource names, tags, descriptions
resource "aws_s3_bucket" "assets" {
  bucket = "my-app-assets-prod-us-east-1"

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    CostCenter  = "engineering"
  }
}

variable "instance_count" {
  default = 3
}

output "db_endpoint" {
  value = aws_db_instance.production.endpoint
}
