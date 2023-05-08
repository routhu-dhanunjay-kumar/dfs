package terraform.aws.naclegress

egress_nacl_cidr_block_check{

    regex.match("^([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})($|/([0-9]{1,2}))$",input.variables.egress_nacl_cidr_block.value)
}

egress_nacl_cidr_block_check_fails{

    not egress_nacl_cidr_block_check
}

egress_rule_number_check{

    x:=input.variables.egress_rule_number.value[_]
    y:=to_number(x)
    y>=1
    y<=32766
}

egress_rule_number_check_fails{

    not egress_rule_number_check
}

valid_port_check_fails{
   x:=input.variables.egress_ports.value[_]
   y:=to_number(x)
   y>65563
}

valid_port_check{
    not valid_port_check_fails
}


allow{
  egress_nacl_cidr_block_check
  egress_rule_number_check
   valid_port_check
}

deny{
    not allow
}
