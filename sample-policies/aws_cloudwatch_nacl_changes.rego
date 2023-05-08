#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  Network Access Control List changes                                 #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_network_acl" in the Terraform code.
    nacls := [resource |
        resource := terraform.aws_network_acl[_]
    ]

    // Check that each NACL has a matching metric filter and alarm resource.
    all(nacls, nacl_has_matching_filter_and_alarm)
}

nacl_has_matching_filter_and_alarm(nacl) {
    // Find a metric filter resource that has a filter pattern that matches NACL changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[nacl.name]
    contains(filter.filter_pattern, "\"eventName\":\"CreateNetworkAcl\"")
    contains(filter.filter_pattern, "\"eventName\":\"DeleteNetworkAcl\"")
    contains(filter.filter_pattern, "\"eventName\":\"UpdateNetworkAcl\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
