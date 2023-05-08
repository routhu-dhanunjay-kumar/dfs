#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  VPC changes                                                         #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_vpc" in the Terraform code.
    vpcs := [resource |
        resource := terraform.aws_vpc[_]
    ]

    // Check that each VPC has a matching metric filter and alarm resource.
    all(vpcs, vpc_has_matching_filter_and_alarm)
}

vpc_has_matching_filter_and_alarm(vpc) {
    // Find a metric filter resource that has a filter pattern that matches VPC changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[vpc.name]
    contains(filter.filter_pattern, "\"eventName\":\"CreateVpc\"")
    contains(filter.filter_pattern, "\"eventName\":\"DeleteVpc\"")
    contains(filter.filter_pattern, "\"eventName\":\"ModifyVpcAttribute\"")
    contains(filter.filter_pattern, "\"eventName\":\"AssociateDhcpOptions\"")
    contains(filter.filter_pattern, "\"eventName\":\"DisassociateDhcpOptions\"")
    contains(filter.filter_pattern, "\"eventName\":\"AttachClassicLinkVpc\"")
    contains(filter.filter_pattern, "\"eventName\":\"DetachClassicLinkVpc\"")
    contains(filter.filter_pattern, "\"eventName\":\"EnableVgwRoutePropagation\"")
    contains(filter.filter_pattern, "\"eventName\":\"DisableVgwRoutePropagation\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
