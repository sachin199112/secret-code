# The AWS region currently being used.
data "aws_region" "current" {
}

# The AWS account id
data "aws_caller_identity" "current" {
}

# The AWS partition (commercial or govcloud)
data "aws_partition" "current" {}
resource "aws_s3_bucket" "secret-events" {
  bucket        = var.s3_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_policy" "secret-events" {
  bucket = aws_s3_bucket.secret-events.id
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
            "Resource": "${aws_s3_bucket.secret-events.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.secret-events.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_sns_topic" "secret-event-sns-topic" {
  name         = "AWS-SECRET-EVENT"
  display_name = "AWS-SECRET-EVENT"
  tags         = var.tags
}

resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  topic_arn = aws_sns_topic.secret-event-sns-topic.arn
  protocol  = "email-json"
  endpoint  = "sachin.kapoor1991@gmail.com"
}
#
# CloudTrail - CloudWatch
#
# This section is used for allowing CloudTrail to send logs to CloudWatch.
#

# This policy allows the CloudTrail service for any account to assume this role.
data "aws_iam_policy_document" "cloudtrail_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

# This role is used by CloudTrail to send logs to CloudWatch.
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name               = var.iam_role_name
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role.json
}

# This CloudWatch Group is used for storing CloudTrail logs.
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = var.cloudwatch_log_group_name
  retention_in_days = var.log_retention_days
  #kms_key_id        = aws_kms_key.cloudtrail.arn
  tags              = var.tags
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_logs" {
  statement {
    sid = "WriteCloudWatchLogs"

    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${var.cloudwatch_log_group_name}:*"]
  }
}

resource "aws_iam_policy" "cloudtrail_cloudwatch_logs" {
  name   = var.iam_policy_name
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_logs.json
}

resource "aws_iam_policy_attachment" "main" {
  name       = "${var.iam_policy_name}-attachment"
  policy_arn = aws_iam_policy.cloudtrail_cloudwatch_logs.arn
  roles      = [aws_iam_role.cloudtrail_cloudwatch_role.name]
}
resource "aws_lambda_permission" "secret-events-lambda" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secret-events-lambda.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
}


resource "aws_cloudwatch_log_subscription_filter" "logging" {
  depends_on      = [aws_lambda_permission.secret-events-lambda]
  destination_arn = aws_lambda_function.secret-events-lambda.arn
  filter_pattern  = "{ $.eventName = \"DescribeSecret\" }"  #jsonencode({ eventName = "DescribeSecret" })#"{ eventName = \"DescribeSecret\" }"                                  #jsonencode({ .eventName = "DescribeSecret" })#"{ eventName = "DescribeSecret" }"                                      #"{\" #"$.eventName\" = \"DescribeSecret\" }" #"\"Exception:\""
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  name            = "describesecret"
}

resource "aws_lambda_function" "secret-events-lambda" {
  filename      = "logging.zip"
  function_name = var.lambda_function_name
  handler       = "main.lambda_handler"
  role          = aws_iam_role.default.arn
  runtime       = "python3.8"
  tags          = var.tags
  environment {
    variables = {
      snstopic = aws_sns_topic.secret-event-sns-topic.arn
    }
  }
}
resource "aws_iam_role_policy" "lambda-policy" {
  name = "secret-event-lambda-policy"
  role = aws_iam_role.default.id

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1:695292474035:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:us-east-1:695292474035:log-group:/aws/lambda/${aws_lambda_function.secret-events-lambda.function_name}:*"
            ]
        },
        {
            "Action": [
                "sns:*"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    
    ]
  })
}
resource "aws_iam_role" "default" {
  name = "sachin-secret-iam_for_lambda_called_from_cloudwatch_logs"
  
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
#

resource "aws_cloudtrail" "main" {
  name = var.trail_name

  # Send logs to CloudWatch Logs
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn

  # Send logs to S3
  s3_key_prefix  = var.s3_key_prefix
  s3_bucket_name = aws_s3_bucket.secret-events.id

  # Note that organization trails can *only* be created in organization
  # master accounts; this will fail if run in a non-master account.
  is_organization_trail = var.org_trail

  # use a single s3 bucket for all aws regions
  is_multi_region_trail = true

  # enable log file validation to detect tampering
  enable_log_file_validation = true

  #kms_key_id = aws_kms_key.cloudtrail.arn

  # Enables logging for the trail. Defaults to true. Setting this to false will pause logging.

  enable_logging = var.enabled
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    exclude_management_event_sources = ["kms.amazonaws.com","rdsdata.amazonaws.com"]
  }

  tags = var.tags

}
