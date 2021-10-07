# dd-terraform
my dd homework

This is a simple terraform template for the given homework
Purpose to show my knowledge on build AWS services with terraform
## content of this repository
* README.md this file
* main.tf main template with resources to create
* variables.tf configuration variables
* outputs.tf defined outputs

it was built with terraform v1.0.8, aws v3.61.0, random v3.1.0
It was required to create 3 tasks
1) creation of CloudTrail in multi region with kms key, s3 buckets and cloudwatch logs enabled.
   Creating a trail with terraform resources is not so easy as documentation is not complete, you need to integrate with AWS documentation,
   such how to create an IAM role for CloudTrail to send logs to CloudWatch 
   https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html
   Another help was given by CloudTrail itself when I had error creating the trail to identify the correct name of the CloudWatch stream prefix
   To identify missing values in policies it's helpful to create a trail in the AWS console and then compare what's different
   In particular how it is built the Resource in the CloudTrail PutLogEvents 
   "Resource" : [
            "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail_log.name}:log-stream:${data.aws_caller_identity.current.account_id}_CloudTrail_${var.region}*"
         ]

The log-stream prefix is composed by: "<AWS Account Id>_CloudTrail_<AWS Region Name>*"
  It requires * at the end!
  Also documentation about kms key policy is missing, so found it looking at the key created by the console after creating a new trail
