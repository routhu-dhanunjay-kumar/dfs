package terraform.aws.transitgateway

transitgateway_name_prefix="transitgateway"

transitgateway_starts_with_prefix{
     startswith(input.variables.tgw_name.value, transitgateway_name_prefix)
}

transitgateway_starts_with_prefix_fail{
     not transitgateway_starts_with_prefix
}

tgw_count_value{
  input.variables.tgw_count.value<=3
}

tgw_count_value_fail{
     not tgw_count_value
}

check_enable_dns_support{
  input.variables.enable_dns_support.value=="enable"
}

check_enable_dns_support_fail{
     not check_enable_dns_support
}


allow {
  transitgateway_starts_with_prefix
  tgw_count_value
  check_enable_dns_support
  print("Policy Success : transitgateway start with prefix and tgw_count_value is also valid and dns support is enabled ")
}

deny{
  not transitgateway_starts_with_prefix
  print("Policy failed : transitgateway not start with prefix")
}

deny{
  not tgw_count_value
  print("Policy failed : tgw_count_value is invalid")
}

deny {
  not check_enable_dns_support
  print("Policy failed : dns support is disabled")
}

