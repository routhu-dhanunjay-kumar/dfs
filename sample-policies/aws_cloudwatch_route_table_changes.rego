#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  route table changes                                                 #
#----------------------------------------------------------------------#

package terraform.aws.logging

import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_route_table" in the Terraform code.
    route_tables := [resource |
        resource := terraform.aws_route_table[_]
    ]

    // Check that each route table has a matching metric filter and alarm resource.
    all(route_tables, route_table_has_matching_filter_and_alarm)
}

route_table_has_matching_filter_and_alarm(route_table) {
    // Find a metric filter resource that has a filter pattern that matches route table changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[route_table.name]
    contains(filter.filter_pattern, "\"eventName\":\"CreateRouteTable\"")
    contains(filter.filter_pattern, "\"eventName\":\"DeleteRouteTable\"")
    contains(filter.filter_pattern, "\"eventName\":\"ReplaceRouteTableAssociation\"")
    contains(filter.filter_pattern, "\"eventName\":\"CreateRoute\"")
    contains(filter.filter_pattern, "\"eventName\":\"DeleteRoute\"")
    contains(filter.filter_pattern, "\"eventName\":\"ReplaceRoute\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
