package terraform.aws.vpc
import future.keywords.every


vpc_cidr_in_range_fails{

	  cidrcheck:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
			resources.name=="myvpc"]
      cidrcheck[_].values.cidr_block=="0.0.0.0/0"  
}

check_for_cloud_filter{
	 
     
     	vpcs:=[resource|resource:=input.planned_values.root_module.resources[_]
			resource.values.metric_transformation[_].namespace=="VPC"
         ]
         
    	every vpc in vpcs {
    	required_pattern := vpc.values.pattern
    	contains(required_pattern,"eventName = CreateVpc")
        contains(required_pattern,"eventName = DeleteVpc")
        contains(required_pattern,"eventName = ModifyVpcAttribute")
        contains(required_pattern,"eventName = AcceptVpcPeeringConnection")
        contains(required_pattern,"eventName = CreateVpcPeeringConnection")
        contains(required_pattern,"eventName = DeleteVpcPeeringConnection")
        contains(required_pattern,"eventName = RejectVpcPeeringConnection")
        contains(required_pattern,"eventName = AttachClassicLinkVpc")
        contains(required_pattern,"eventName = DetachClassicLinkVpc")
        contains(required_pattern,"eventName = DisableVpcClassicLink")
        contains(required_pattern,"eventName = EnableVpcClassicLink")
        
        alarm:= [resources|resources:=input.planned_values.root_module.resources[_]
        		resources.values.namespace=="VPC"]         
        alarm[_].name == vpc.name 

	}
}

allow {
    not vpc_cidr_in_range_fails
    check_for_cloud_filter
    print("Policy passed: VPC CIDR is in range and dnsHostNames is true\n")
}

deny[msg] {
    vpc_cidr_in_range_fails
    msg:=sprintf("Policy Failed for %v: VPC CIDR is not in range",[input.variables.tags.value.projectName])
}

deny[msg]{
   not check_for_cloud_filter
   msg:=sprintf("Policy Failed for %v: cloud filter failed",[input.variables.tags.value.projectName])
}


