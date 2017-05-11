# aws-parameter-syncer
Keep file contents in sync with matching parameters in AWS Parameter Store

## Variables

- VERBOSE - enable more logging if set to 1
- UMASK - optional UMASK value to use for files created
- FREQUENCY - How often to check for changes (in seconds). Default is 300 seconds (5 minutes).
- AWS_ACCESS_KEY_ID - The AWS Access Key Id value
- AWS_SECRET_ACCESS_KEY - The AWS Secret Access Key value
- AWS_REGION - AWS Region to search (defaults to us-east-1)
- PARAM_PREFIX - The prefix for the parameters to keep in sync
    - resulting filenames will be the parameter name minus the PARAM_PREFIX
    - eg. Following parameters in parameter store: TESTING_param1.txt, TESTING_param2.conf
        - export PARAM_PREFIX=TESTING_
        - TESTING_param1.txt will be compared against param1.txt
        - TESTING_param2.conf will be compared against param2.conf

The docker container exposes /credentials as a volume - this can be shared with other
containers or mounted to the local file system


## Example Docker runs


This example checks AWS Parameter Store in the default us-east-1 region every 600 seconds (10 minutes)
for parameters containing 'TESTING_'. The credentials in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are
used to access the AWS Parameter Store. The parameter values will be checked against files in the local
folder 'credentials-dir' which is mounted into the container at '/credentials'.


````
docker run -d -e "FREQUENCY=600" \
 -e "VERBOSE=1" \
 -e "AWS_ACCESS_KEY_ID=MY_ACCESS_KEY_ID \
 -e "AWS_SECRET_ACCESS_KEY=MY_SECRET_KEY \
 -e "PARAM_PREFIX=TESTING_" \
 -v credentials-dir:/credentials \
 signiant/aws-parameter-syncer
````

This example checks AWS Parameter Store in the us-west-2 region every 120 seconds (2 minutes)
for parameters containing 'TESTING_'. The credentials in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are
used to access the AWS Parameter Store. The parameter values will be checked against files in the container
volume '/credentials' which is NOT mounted locally. This volume could be shared with other containers if
desired.


````
docker run -d -e "FREQUENCY=120" \
 -e "AWS_ACCESS_KEY_ID=MY_ACCESS_KEY_ID \
 -e "AWS_SECRET_ACCESS_KEY=MY_SECRET_KEY \
 -e "AWS_REGION=us-west-2"
 -e "PARAM_PREFIX=TESTING_" \
 signiant/aws-parameter-syncer
````





