#----------------------------------------------------------------------#
# CIS Policy: to ensure the default AWS Security Group of each         #
#  VPC restricts all traffic                                           #
#----------------------------------------------------------------------#

package aws.security

import data.aws.ec2.security_groups
import data.aws.ec2.vpcs

default_security_group_restricted {
    vpc := vpcs[_]
    sg := security_groups[_]
    sg.group_name == "default"
    sg.vpc_id == vpc.vpc_id
    not sg.ip_permissions[_]
    not sg.ip_permissions_egress[_]
}
