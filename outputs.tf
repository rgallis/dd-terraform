output "CloudTrail" {
  description = "CloudTrail rail"
  value       = aws_cloudtrail.cloudtrail.name
}

output "S3bucket" {
  description = "S3 Bucket for CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_bucket.bucket
  
}
