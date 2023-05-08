#----------------------------------------------------------------------#
# CIS Policy: to ensure that no AWS SGs allow ingress from 0.0.0.0/0 #
#  to remote server administration ports in Terraform code             #
#----------------------------------------------------------------------#

package terraform.aws.securitygroup
import data.terraform

default allow = false

allow {
    sg := terraform.aws_security_group[_]
    rule := sg.ingress[_]
    cidr_block := rule.cidr_blocks[_]
    ports := [22, 3389, 5985, 5986] // add any other administration ports as necessary
    contains(ports, rule.to_port)
    cidr_block == "0.0.0.0/0"
}
