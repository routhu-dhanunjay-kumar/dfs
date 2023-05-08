
package terraform.aws.routetable
import future.keywords.every


check_for_route_table_cloud_filter
{
      routetables:=[resource|resource:=input.planned_values.root_module.resources[_]
      	resource.values.metric_transformation[_].namespace=="routetable"]

	 every routetable in routetables{
       	 required_pattern:=routetable.values.pattern
         contains(required_pattern,"eventName = CreateRoute")
         contains(required_pattern,"eventName = CreateRouteTable")
         contains(required_pattern,"eventName = ReplaceRoute")
         contains(required_pattern,"eventName = ReplaceRouteTableAssociation")
         contains(required_pattern,"eventName = DeleteRouteTable")
         contains(required_pattern,"eventName = DeleteRoute")
         contains(required_pattern,"eventName = DisassociateRouteTable")
         

	   alarm:= [resources|resources:=input.planned_values.root_module.resources[_]
      	   resources.values.namespace=="routetable"]   
   
	   alarm[_].name==routetable.name
	   }
}

allow {
  check_for_route_table_cloud_filter
  print("Route Table policy success")
}

deny[msg]{
   not check_for_route_table_cloud_filter
   msg:=sprintf("Policy Failed for %v route table : cloud filter failed",[input.variables.tags.value.projectName])
}
