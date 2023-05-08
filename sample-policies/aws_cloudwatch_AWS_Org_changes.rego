#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  AWS Organizations changes                                           #
#----------------------------------------------------------------------#

package terraform.aws

import data.terraform.resources as resources

default allow = false

# Ensure log metric filter exists for AWS Organizations changes
violation[msg] {
    not resources.aws_cloudwatch_metric_filter["org_changes"]
    msg = "Log metric filter for AWS Organizations changes does not exist"
}

# Ensure CloudWatch alarm exists for AWS Organizations changes
violation[msg] {
    not resources.aws_cloudwatch_metric_alarm["org_changes"]
    msg = "CloudWatch alarm for AWS Organizations changes does not exist"
}

# Allow when both conditions are satisfied
allow {
    resources.aws_cloudwatch_metric_filter["org_changes"]
    resources.aws_cloudwatch_metric_alarm["org_changes"]
}
