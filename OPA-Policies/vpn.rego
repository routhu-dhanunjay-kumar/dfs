package terraform.aws.vpn

vpn_connection_type_check{
    input.variables.vpn_connection_type.value=="ipsec.1"
}

vpn_connection_type_check_fail{
   not vpn_connection_type_check
}

vpn_connection_tunnel1_startup_action_check{
    input.variables.vpn_connection_tunnel1_startup_action.value=="add"
}

vpn_connection_tunnel1_startup_action_check_fail{
    not vpn_connection_tunnel1_startup_action_check
}

vpn_gateway_name_check{
    startswith(input.variables.vpn_gateway_name.value,"vpn-")
}

vpn_gateway_name_check_fail{
    not vpn_gateway_name_check
}

vpn_connection_static_routes_only_check{
    input.variables.vpn_connection_static_routes_only.value=="true"
}

vpn_connection_static_routes_only_check_fail{
    not vpn_connection_static_routes_only_check
}


allow {
     vpn_connection_type_check
     vpn_connection_tunnel1_startup_action_check
     vpn_gateway_name_check
     vpn_connection_static_routes_only_check
     print("Policy Passed : vpn connection type is correct and vpn connection tunnel1 startup action is valid and vpn gateway name is correct and vpn connection static routes value is correct")

}

deny{
    not vpn_connection_type_check
    print("Policy Failed : vpn connection type is incorrect")
}

deny{
    not vpn_connection_tunnel1_startup_action_check
    print("Policy Failed : vpn connection tunnel1 startup action is invalid")
}

deny{
    not vpn_gateway_name_check
    print("Policy Failed : vpn gateway name is incorrect")
}

deny{
    not vpn_connection_static_routes_only_check
    print("Policy Failed : vpn connection static routes value is incorrect")
}
