#----------------------------------------------------------------------#
# CIS Policy: to ensure AWS routing table for VPC peering              #
#  are least access                                                    #
#----------------------------------------------------------------------#

package terraform.aws.routing
import data.terraform

default allow = false

allow {
    rt := terraform.aws_route_table[_]
    route := rt.route[_]
    is_peering_route := route.vpc_peering_connection_id != null
    cidr_block := route.cidr_block
    cidr_block != "0.0.0.0/0"
    not startswith(cidr_block, "10.") // exclude RFC 1918 private addresses
    not startswith(cidr_block, "172.16.")
    not startswith(cidr_block, "192.168.")
    not is_peering_route // reject VPC peering routes
}
