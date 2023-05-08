package terraform.aws.ec2

ec2_alarm_threshold_check{

	ec2s := [resource |
        resource := input.planned_values.root_module.resources[_];
        resource.name=="ec2-alarm"
    ]
    ec2s[_].values.metric_name=="CPUUtilization"
    ec2s[_].values.threshold<=80
}

ec2_alarm_threshold_check_fails{
not ec2_alarm_threshold_check
}

allow{
  ec2_alarm_threshold_check
}
  
deny{
  not ec2_alarm_threshold_check
}
