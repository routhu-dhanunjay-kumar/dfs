package terraform.aws.nacl

import future.keywords.every

check_for_nacl_cloud_filter{
	nacls:=[resource|resource:=input.planned_values.root_module.resources[_];
                	resource.values.metric_transformation[_].namespace=="NACL"]
                        
                        
      every nacl in nacls{
      required_pattern:=nacl.values.pattern
      
        contains(required_pattern,"eventName = CreateNetworkAcl")
        contains(required_pattern,"eventName = CreateNetworkAclEntry")
        contains(required_pattern,"eventName = DeleteNetworkAcl")
        contains(required_pattern,"eventName = DeleteNetworkAclEntry")
        contains(required_pattern,"eventName = ReplaceNetworkAclEntry")
        contains(required_pattern,"eventName = ReplaceNetworkAclAssociation")
        
        alarm:= [resources|resources:=input.planned_values.root_module.resources[_]
    	resources.values.namespace=="NACL"]   
          
		alarm[_].name==nacl.name
        
	}
}

allow{
	check_for_nacl_cloud_filter
}

deny[msg]{
	not check_for_nacl_cloud_filter
    msg:=sprintf("Policy Failed for %v: NACL cloud filter failed",[input.variables.tags.value.projectName])
    
}
