Update the trust policy for aws-elasticbeanstalk-service-role to this in order to resolve issues assuming the role:

{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "",
			"Effect": "Allow",
			"Principal": {
				"Service": "elasticbeanstalk.amazonaws.com"
			},
			"Action": "sts:AssumeRole",
			"Condition": {
				"StringEquals": {
					"sts:ExternalId": "elasticbeanstalk"
				}
			}
		}
	]
}