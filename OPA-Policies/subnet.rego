package terraform.aws.subnet

subnet_cidr_in_range_fail{
    
    cidrcheck:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
				resources.name=="subnet"]
     cidrcheck[_].values.cidr_block=="0.0.0.0/0"
}

subnet_cidr_in_range{
    not subnet_cidr_in_range_fail
}


allow {
    subnet_cidr_in_range
    print("Policy Passed for subnet : subnet_cidr_is in range")
}

deny {
    not subnet_cidr_in_range
    print(" Policy Failed :Subnet CIDR block is not in range\n")
}

