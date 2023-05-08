#----------------------------------------------------------------------#
# CIS Policy: to ensure that no AWS NACLs allow ingress from 0.0.0.0/0 #
#  to remote server administration ports in Terraform code             #
#----------------------------------------------------------------------#


package terraform.aws.nacl
import data.terraform

default allow = false

allow {
    nacl := terraform.aws_network_acl[_]
    rule := nacl.ingress[_]
    cidr_block := rule.cidr_block
    ports := [22, 3389, 5985, 5986] // add any other administration ports as necessary
    contains(ports, rule.to_port)
    cidr_block == "0.0.0.0/0"
}
