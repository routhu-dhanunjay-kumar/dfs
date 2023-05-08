#----------------------------------------------------------------------#
# CIS Policy: to ensure VPC Flow Logs is enabled in all VPCs           #
#----------------------------------------------------------------------#

package aws.vpc

import "github.com/open-policy-agent/opa/bundle"
import data.aws_vpc as vpc

default allow = false

# Ensure VPC Flow Logs are enabled in all VPCs
violation[msg] {
    some vpc_id
    not vpc.flow_logs[vpc_id]
    msg = sprintf("VPC Flow Logs not enabled in VPC %s", [vpc_id])
}

# Allow when VPC Flow Logs are enabled in all VPCs
allow {
    all vpc_id
    vpc.flow_logs[vpc_id]
}
