#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  Security Group changes                                              #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_security_group" in the Terraform code.
    groups := [resource |
        resource := terraform.aws_security_group[_]
    ]

    // Check that each group has a matching metric filter and alarm resource.
    all(groups, group_has_matching_filter_and_alarm)
}

group_has_matching_filter_and_alarm(group) {
    // Find a metric filter resource that has a filter pattern that matches Security Group changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[group.name]
    contains(filter.filter_pattern, "eventName\":\"AuthorizeSecurityGroupIngress\",\"eventSource\":\"ec2.amazonaws.com\"")
    contains(filter.filter_pattern, "eventName\":\"AuthorizeSecurityGroupEgress\",\"eventSource\":\"ec2.amazonaws.com\"")
    contains(filter.filter_pattern, "eventName\":\"RevokeSecurityGroupIngress\",\"eventSource\":\"ec2.amazonaws.com\"")
    contains(filter.filter_pattern, "eventName\":\"RevokeSecurityGroupEgress\",\"eventSource\":\"ec2.amazonaws.com\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
