#----------------------------------------------------------------------#
# CIS Policy: to ensure AWS security hub is enabled                    #
#----------------------------------------------------------------------#

package aws.securityhub
import data.aws_securityhub_account as sh_account

default allow = false

# Check if AWS Security Hub is enabled
violation[msg] {
    not sh_account.current.enabled
    msg = "AWS Security Hub is not enabled"
}

# Allow when AWS Security Hub is enabled
allow {
    sh_account.current.enabled
}
