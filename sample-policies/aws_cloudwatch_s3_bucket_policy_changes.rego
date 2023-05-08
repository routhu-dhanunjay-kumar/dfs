#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  S3 Bucket policy changes                                            #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_s3_bucket_policy" in the Terraform code.
    bucket_policies := [resource |
        resource := terraform.aws_s3_bucket_policy[_]
    ]

    // Check that each bucket policy has a matching metric filter and alarm resource.
    all(bucket_policies, policy_has_matching_filter_and_alarm)
}

policy_has_matching_filter_and_alarm(policy) {
    // Check that the policy has a "PutBucketPolicy" or "DeleteBucketPolicy" statement.
    statement := policy.policy
    contains(statement, "PutBucketPolicy")
    contains(statement, "DeleteBucketPolicy")

    // Find a metric filter resource that has a filter pattern that matches S3 Bucket policy changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[policy.name]
    contains(filter.filter_pattern, "eventName\":\"PutBucketPolicy\"")
    contains(filter.filter_pattern, "eventName\":\"DeleteBucketPolicy\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
