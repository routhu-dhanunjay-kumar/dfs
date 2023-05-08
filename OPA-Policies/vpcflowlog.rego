package terraform.aws.vpcflowlog

vpcflowlog_name_prefix = "vpcflowlog"

vpcflowlog_name_starts_with_prefix {
    startswith(input.variables.flowlog_name.value, vpcflowlog_name_prefix)
}

vpcflowlog_name_starts_with_prefix_fail{
    not vpcflowlog_name_starts_with_prefix
}

create_aws_flow_log_check{
    input.variables.create_aws_flow_log.value=="true"
}

create_aws_flow_log_check_fail{
    not create_aws_flow_log_check
}


allow {
    vpcflowlog_name_starts_with_prefix
    create_aws_flow_log_check
    print("Policy Success: vpc flowlog starts with prefix and aws flow log value is true")
}

deny {
    not vpcflowlog_name_starts_with_prefix
    print("Policy failed: vpc flowlog not starts with prefix")
}

deny {
    not create_aws_flow_log_check
    print("Policy failed: aws flow log value is not true")
}
