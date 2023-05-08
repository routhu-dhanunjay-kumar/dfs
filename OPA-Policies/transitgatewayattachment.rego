package terraform.aws.transitgatewayattachment

transitgatewayattachment_name_prefix="transitgatewayattachment"


#transit_gateway_default_route_table_association_check{
#  input.variables.transit_gateway_default_route_table_association.value=="false"
#}

#transit_gateway_default_route_table_association_check_fail{
#  not transit_gateway_default_route_table_association_check
#}



transitgatewayattachment_starts_with_prefix{
     startswith(input.variables.attachment_name.value, transitgatewayattachment_name_prefix)
}

transitgatewayattachment_starts_with_prefix_fail{
  not transitgatewayattachment_starts_with_prefix
}

allow {
    transitgatewayattachment_starts_with_prefix
    #transit_gateway_default_route_table_association_check
    print("Policy passed: Transit Gateway attachment name starts with transitgatewayattachment and create_tgw_rtable_route and transit_gateway_default_route_table_association and transit_gateway_default_route_table_propagation \n")
}
 deny{
   not transitgatewayattachment_starts_with_prefix
   print("Policy Failed :Transitgateway attachment name is incorrect")
 }
 #deny{
  #  not transit_gateway_default_route_table_association_check
  #  print("Policy Failed :Transitgateway default route table association check failed")
 #}
 
