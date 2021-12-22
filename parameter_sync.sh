#!/bin/bash

if [ "$VERBOSE" ]; then
    echo "Verbose logging enabled"
    set -x
    VERBOSE='--verbose'
fi

if [ "$UMASK" ]; then
    echo "setting given UMASK - all files and folders created will use a umask value of $UMASK"
    umask $UMASK
fi

# Check for required ENV Variables

if [ -z "$CRED_FOLDER_PATH" ]; then
    CRED_FOLDER_PATH=/credentials
fi

if [ -z "$PARAM_PREFIX" ]; then
    echo "Must supply a parameter prefix by setting the PARAM_PREFIX environment variable"
    exit 1
else
    echo "Parameter Prefix set to $PARAM_PREFIX"
fi

if [ -z "$AWS_REGION" ]; then
    echo "AWS_REGION not set - defaulting to us-east-1"
    AWS_REGION='us-east-1'
fi

# Set a default frequency of 300 seconds if not set in the env
if [ -z "$FREQUENCY" ]; then
    echo "FREQUENCY not set - defaulting to 300 seconds"
    FREQUENCY=300
else
    echo "Frequency set to $FREQUENCY seconds"
fi

# Loop forever, sleeping for our frequency
while true
do
    echo "Awoke to check for new credentials with prefix ${PARAM_PREFIX} in AWS Parameter Store"

    python /parameter_sync.py --credentials-path ${CRED_FOLDER_PATH} --param-prefix ${PARAM_PREFIX} --aws-region ${AWS_REGION} ${VERBOSE}
    echo "Sleeping for $FREQUENCY seconds"
    sleep $FREQUENCY
    echo
done

exit 0
