package terraform.aws.route

route_destination_check{
  input.variables.destination_cidr_block.value!="0.0.0.0/1"
}

route_destination_check_fails{
  not route_destination_check
}

allow{
  route_destination_check
 }
 
 deny{
  not allow
 }
  
