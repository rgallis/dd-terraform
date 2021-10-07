provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

resource "random_string" "random" {
  length  = 8
  special = false
  lower   = true
  upper   = false
}

resource "aws_kms_key" "cloudtrail_log" {
  description             = "KMS key for cloudtrail"
  deletion_window_in_days = 10
  policy = jsonencode({
    "Version": "2012-10-17",
    "Id": "Key policy created by CloudTrail",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow CloudTrail to encrypt logs",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "kms:GenerateDataKey*",
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
                }
            }
        },
        {
            "Sid": "Allow CloudTrail to describe key",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "kms:DescribeKey",
            "Resource": "*"
        },
        {
            "Sid": "Allow principals in the account to decrypt log files",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
                }
            }
        },
        {
            "Sid": "Allow alias creation during setup",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:CreateAlias",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${data.aws_caller_identity.current.account_id}",
                    "kms:ViaService": "ec2.eu-west-1.amazonaws.com"
                }
            }
        },
        {
            "Sid": "Enable cross account log decryption",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
                }
            }
        }
    ]
})
}
# show cloudtrail_log kms key alias in the console
resource "aws_kms_alias" "cloudtrail_log" {
  name          = "alias/cloudtrail_log_key"
  target_key_id = aws_kms_key.cloudtrail_log.key_id
}
# create an S3 bucket to store cloudtrail logs, the name contains random string to avoid S3 name conflicts
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = join("-", ["cloudtrail-logs", random_string.random.result]) # generate random string to join S3 name
  force_destroy = true
}
# S3 bucket policy definition to allow CloudTrail access
resource "aws_s3_bucket_policy" "cloudtrail_bucket" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.cloudtrail_bucket.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${aws_s3_bucket.cloudtrail_bucket.bucket}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
  depends_on = [
    aws_s3_bucket.cloudtrail_bucket # need to wait bucket creation before applying the policy
  ]
}
# restrict public access to the bucket
resource "aws_s3_bucket_public_access_block" "s3public" {
  bucket                  = aws_s3_bucket.cloudtrail_bucket.id
  restrict_public_buckets = true
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  depends_on = [
    aws_s3_bucket.cloudtrail_bucket,
    aws_s3_bucket_policy.cloudtrail_bucket
  ]

}



# CloudWatch log group definition for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail_log" {
  name = "CloudTrail_Log"
}
# CloudWatch log stream required by CloudTrail 
resource "aws_cloudwatch_log_stream" "cloudtrail_log" {
  name           = "CloudTrail_Log_Stream"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_log.name
}

# IAM role required by CloudTrail to send logs to CloudWatch
resource "aws_iam_role" "cloudtrail_log" {
  name = "CloudTrail_role_for_Cloudwatch"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "cloudtrail.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
 # inline_policy is required by CloudTrail to integrate with CloudWatch
  inline_policy {
    name = "CloudTrailPolicyForCloudWatch"
    policy = jsonencode({
      "Version" : "2012-10-17",
      "Statement" : [
        {

          "Sid" : "AWSCloudTrailCreateLogStream2014110",
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogStream"
          ],
          "Resource" : [
            "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_log.name}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_${var.region}*"
          ]

        },
        {
          "Sid" : "AWSCloudTrailPutLogEvents20141101",
          "Effect" : "Allow",
          "Action" : [
            "logs:PutLogEvents"
          ],
          "Resource" : [
            "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_log.name}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_${var.region}*"
          ]
        }
      ]
    })
  }
  # the IAM policy needs to be built after cloudwatch log group
  depends_on = [
    aws_cloudwatch_log_group.cloudtrail_log,
    aws_cloudwatch_log_stream.cloudtrail_log
  ]
}


resource "aws_cloudtrail" "cloudtrail" {
  name                          = "rob-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  s3_key_prefix                 = "prefix"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail_log.arn}:*"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail_log.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_log.arn
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
  depends_on = [
    aws_s3_bucket.cloudtrail_bucket,
    aws_s3_bucket_policy.cloudtrail_bucket,
    aws_cloudwatch_log_group.cloudtrail_log,
    aws_cloudwatch_log_stream.cloudtrail_log,
    aws_iam_role.cloudtrail_log,
    aws_kms_key.cloudtrail_log
  ]
}
