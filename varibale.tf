variable "cloudwatch_log_group_name" {
  description = "The name of the CloudWatch Log Group that receives CloudTrail events."
  default     = "sachin-cloudtrail-events"
  type        = string
}

variable "enabled" {
  description = "Enables logging for the trail. Defaults to true. Setting this to false will pause logging."
  default     = true
  type        = bool
}

variable "log_retention_days" {
  description = "Number of days to keep AWS logs around in specific log group."
  default     = 30
  type        = string
}

variable "s3_bucket_name" {
  description = "The name of the AWS S3 bucket."
  default     = "sachin-test-cloudwatch"
  type        = string

}

variable "org_trail" {
  description = "Whether or not this is an organization trail. Only valid in master account."
  default     = "false"
  type        = string
}

variable "emailid" {
  description = "Duration in days after which the key is deleted after destruction of the resource, must be 7-30 days.  Default 30 days."
  default     = "sachin.kapoor1991@gmail.com"
  type        = string
}

variable "trail_name" {
  description = "Name for the Cloudtrail"
  default     = "secret-event-cloudtrail"
  type        = string
}
variable "lambda_function_name" {
  description = "Name for the Cloudtrail"
  default     = "secret-event-lamda-code"
  type        = string
}

variable "iam_role_name" {
  description = "Name for the CloudTrail IAM role"
  default     = "secret-event-cloudtrail-cloudwatch-logs-role"
  type        = string
}

variable "iam_role_name_for_lambda" {
  description = "Name for the CloudTrail IAM role"
  default     = "secret-event-lambda-role"
  type        = string
}

variable "iam_policy_name" {
  description = "Name for the CloudTrail IAM policy"
  default     = "secret-event-cloudtrail-cloudwatch-logs-policy"
  type        = string
}

variable "s3_key_prefix" {
  description = "S3 key prefix for CloudTrail logs"
  default     = "prefix"
  type        = string
}

variable "tags" {
  description = "A mapping of tags to CloudTrail resources."
  default     = { Automation = "sachin-Terraform" }
  type        = map(string)
}
