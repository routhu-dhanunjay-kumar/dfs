package terraform.aws.iamrole

max_session_duration_check{
    #session_duration>=3600
    #session_duration<=43200
    session_duration:= [resources|resources:=input.planned_values.root_module.child_modules[_].resources[_]
			resources.name=="iamrole"]
      session_duration[_].values.max_session_duration>=3600
      session_duration[_].values.max_session_duration<=43200
      
}

allow {
    max_session_duration_check
    print("Policy passing for iamrole name start_with_prefix and session duration is in range ")
}

deny[msg]{
    not max_session_duration_check
    msg:=sprintf(" for %v i_am role session duration check fails",[input.variables.tags.value.projectName])
}


