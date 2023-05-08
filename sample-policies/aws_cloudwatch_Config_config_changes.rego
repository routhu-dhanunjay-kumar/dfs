#----------------------------------------------------------------------#
# CIS Policy: to ensure a log metric filter and alarm exist for        #
#  AWS Config configuration changes                                    #
#----------------------------------------------------------------------#

package terraform.aws.logging
import data.terraform

default allow = false

allow {
    // Find all resources of type "aws_config_configuration_recorder" in the Terraform code.
    recorders := [resource |
        resource := terraform.aws_config_configuration_recorder[_]
    ]

    // Check that each recorder has a matching metric filter and alarm resource.
    all(recorders, recorder_has_matching_filter_and_alarm)
}

recorder_has_matching_filter_and_alarm(recorder) {
    // Find a metric filter resource that has a filter pattern that matches AWS Config configuration changes.
    filter := terraform.aws_cloudwatch_log_metric_filter[recorder.name]
    contains(filter.filter_pattern, "eventName\":\"PutConfigurationRecorder\",\"eventSource\":\"config.amazonaws.com\"")

    // Find an alarm resource that has the same name and dimensions as the metric filter.
    alarm := terraform.aws_cloudwatch_metric_alarm[filter.name]
    alarm.name == filter.name
    alarm.dimensions == filter.metric_transformation.dimensions
}
