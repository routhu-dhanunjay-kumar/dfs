package terraform.aws.securitygroup

import future.keywords.every

check_for_security_group_cloud_filter{

	 securitygroups:=[resource|resource:=input.planned_values.root_module.resources[_];
                        resource.address=="aws_cloudwatch_log_metric_filter.security_group_changes"
                        ]
                        
                        
          every securitygroup in securitygroups{
      		required_pattern:=securitygroup.values.pattern
      
        	contains(required_pattern,"eventName = AuthorizeSecurityGroupIngress")
        	contains(required_pattern,"eventName = AuthorizeSecurityGroupEgress")
       	    	contains(required_pattern,"eventName = RevokeSecurityGroupIngress")
        	contains(required_pattern,"eventName = RevokeSecurityGroupEgress")
        	contains(required_pattern,"eventName = CreateSecurityGroup")
        	contains(required_pattern,"eventName = DeleteSecurityGroup")
        
       	 	alarm:= [resources|resources:=input.planned_values.root_module.resources[_]
    	 	resources.address=="aws_cloudwatch_metric_alarm.security_group_changes"]   
          
		alarm[_].name==securitygroup.name
        
        }
        

}

check_for_security_group_cloud_filter_fails{
	not check_for_security_group_cloud_filter
}
allow{
	check_for_security_group_cloud_filter
}
deny{
	not allow
}
