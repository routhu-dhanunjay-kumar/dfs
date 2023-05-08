package terraform.aws.naclingress

ingress_nacl_cidr_block_check{

    naclrules:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
 				resources.name=="nacl_rules"
			]
   regex.match("^([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})($|/([0-9]{1,2}))$",naclrules[_].values.cidr_block)    
            
}

ingress_rule_number_check
{

    naclrules:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
  				resources.name=="nacl_rules"
			]
    value:=naclrules[_].values.rule_number
    value>=1
    value<=32766
}

valid_to_port_check_fails{

  naclrules:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
  				resources.name=="nacl_rules"
			]
    value:=naclrules[_].values.to_port
    
   value>65563
}

valid_from_port_check_fails{

  naclrules:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
  				resources.name=="nacl_rules"
			]
    value:=naclrules[_].values.from_port
    
   value>65563
}

allow{
    ingress_nacl_cidr_block_check
    ingress_rule_number_check
    not valid_to_port_check_fails
    not valid_from_port_check_fails
}

deny[msg]{
	not ingress_nacl_cidr_block_check
    msg:=sprintf("Policy Failed for %v: Ingress Cidr block",[input.variables.tags.value.projectName])
}

deny[msg]{
	not ingress_rule_number_check
    msg:=sprintf("Policy Failed for %v: Ingress Rule",[input.variables.tags.value.projectName])
}
deny[msg]{
	 valid_to_port_check_fails
      msg:=sprintf("Policy Failed for %v: Invalid to port",[input.variables.tags.value.projectName])
}

deny[msg]{
	 valid_from_port_check_fails
      msg:=sprintf("Policy Failed for %v: Invalid from port",[input.variables.tags.value.projectName])
}
