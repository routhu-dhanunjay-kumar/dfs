#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  changes to Network Gateways                                         #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_vpn_gateway" in the Terraform code.
    gateways := [resource |
        resource := terraform.aws_vpn_gateway[_]
    ]

    // Check that each VPN Gateway has a matching metric filter and alarm resource.
    all(gateways, gateway_has_matching_filter_and_alarm)
}

gateway_has_matching_filter_and_alarm(gateway) {
    // Find a metric filter resource that has a filter pattern that matches VPN Gateway changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[gateway.name]
    contains(filter.filter_pattern, "\"eventName\":\"CreateVpnGateway\"")
    contains(filter.filter_pattern, "\"eventName\":\"DeleteVpnGateway\"")
    contains(filter.filter_pattern, "\"eventName\":\"ModifyVpnGateway\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
