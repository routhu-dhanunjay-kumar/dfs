#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  AWS IAM policy changes                                              #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_cloudwatch_log_metric_filter" in the Terraform code.
    metric_filters := [resource |
        resource := terraform.aws_cloudwatch_log_metric_filter[_]
    ]

    // Check that each metric filter has a matching alarm resource.
    all(metric_filters, filter_has_matching_alarm)
}

filter_has_matching_alarm(filter) {
    // Check that the metric filter has a filter pattern that matches IAM policy changes.
    filter_pattern := filter.filter_pattern
    contains(filter_pattern, "\"eventName\": \"PutGroupPolicy\"")
    contains(filter_pattern, "\"eventName\": \"PutRolePolicy\"")
    contains(filter_pattern, "\"eventName\": \"PutUserPolicy\"")
    contains(filter_pattern, "\"eventName\": \"CreatePolicy\"")
    contains(filter_pattern, "\"eventName\": \"DeletePolicy\"")
    contains(filter_pattern, "\"eventName\": \"AttachRolePolicy\"")
    contains(filter_pattern, "\"eventName\": \"DetachRolePolicy\"")
    contains(filter_pattern, "\"eventName\": \"AttachUserPolicy\"")
    contains(filter_pattern, "\"eventName\": \"DetachUserPolicy\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
