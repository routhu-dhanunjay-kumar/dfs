package terraform.aws.iampolicy
import future.keywords.every


check_for_iam_policy_cloud_filter{

      iampolicys:=[resource|resource:=input.planned_values.root_module.resources[_]
      resource.values.metric_transformation[_].namespace=="IAMpolicy"]
      
       every iampolicy in iampolicys{

       required_pattern:=iampolicy.values.pattern
         contains(required_pattern,"eventName=CreatePolicy")
         contains(required_pattern,"eventName=CreatePolicyVersion")
         contains(required_pattern,"eventName=DeleteUserPolicy")
         contains(required_pattern,"eventName=DeleteGroupPolicy")
         contains(required_pattern,"eventName=DeleteRolePolicy")
         contains(required_pattern,"eventName=PutGroupPolicy")
         contains(required_pattern,"eventName=PutRolePolicy")
         contains(required_pattern,"eventName=PutUserPolicy")
         contains(required_pattern,"eventName=DeletePolicy")
         contains(required_pattern,"eventName=DeletePolicyVersion")
         contains(required_pattern,"eventName=AttachRolePolicy")
         contains(required_pattern,"eventName=DetachRolePolicy")
         contains(required_pattern,"eventName=AttachUserPolicy")
         contains(required_pattern,"eventName=DetachUserPolicy")
         contains(required_pattern,"eventName=AttachGroupPolicy")
         contains(required_pattern,"eventName=DetachGroupPolicy")
        

	   alarm:= [resources|resources:=input.planned_values.root_module.resources[_]
       		resources.values.namespace=="IAMpolicy"]   
          
	   alarm[_].name==iampolicy.name
	   }
}

allow{
	check_for_iam_policy_cloud_filter
}
deny[msg]{
	not allow
    msg:=sprintf("Policy Failed for %v IAM Policy :cloud filter failed",[input.variables.tags.value.projectName])
}
