import logging, logging.handlers
import argparse
import os
import boto3
import hashlib
import tempfile
import shutil

logging.getLogger("botocore").setLevel(logging.CRITICAL)

def get_sha256_hash(file_path):
    logging.debug('Hashing "%s" using SHA256' % file_path)
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    logging.debug('   SHA256 hash: {0}'.format(sha256.hexdigest()))
    return sha256.digest()


def process_parameters_with_prefix(param_prefix, cred_path, aws_region, aws_access_key=None, aws_secret_key=None, dryrun=False):
    logging.debug('Searching for parameters with a prefix of %s' % param_prefix)

    def get_parameters(parameter_names_list):
        parameter_list = []
        if parameter_names_list:
            result = ssm.get_parameters(Names=parameter_names_list, WithDecryption=True)
            if result:
                if 'ResponseMetadata' in result:
                    if 'HTTPStatusCode' in result['ResponseMetadata']:
                        if result['ResponseMetadata']['HTTPStatusCode'] == 200:
                            if 'Parameters' in result:
                                parameter_list = result['Parameters']
        return parameter_list

    def process_parameter(param_name, param_value):
        filename = param_name.split(param_prefix)[1]
        full_cred_path = cred_path + os.sep + filename
        existing_file_sha256_hash = None
        if os.path.exists(full_cred_path):
            existing_file_sha256_hash = get_sha256_hash(full_cred_path)
        new_file_full_path = temp_dir + os.sep + filename + '.new'
        logging.debug('Storing retrieved value for parameter "%s" in "%s"' % (param_name, new_file_full_path))
        with open(new_file_full_path, 'w') as f:
            f.write(param_value.replace('\\n', '\n'))
        new_file_sha256_hash = get_sha256_hash(new_file_full_path)
        logging.debug('Comparing file hashes')
        if existing_file_sha256_hash != new_file_sha256_hash:
            if not existing_file_sha256_hash:
                logging.info('This is a new credentials file: "%s"' % filename)
            else:
                logging.info("Contents don't match - replacing \"%s\" contents with value from parameter store" % full_cred_path)
            if not dryrun:
                if os.path.exists(new_file_full_path) and os.stat(new_file_full_path).st_size > 0:
                    shutil.copyfile(new_file_full_path, full_cred_path)
                else:
                    logging.error('file %s is missing or zero length - NOT replacing' % new_file_full_path)
            else:
                logging.info('*** Dryrun selected - will NOT update "%s"' % full_cred_path)
        else:
            logging.info('Contents of existing "%s" MATCH with value for "%s" from parameter store' % (full_cred_path, param_name))

        # Cleanup
        if new_file_full_path:
            logging.debug('Removing %s' % new_file_full_path)
            os.remove(new_file_full_path)

    def get_parameters_with_prefix(prefix, next_token=None):
        parameter_list = []
        if next_token:
            query_result = ssm.describe_parameters(Filters=[{'Key': 'Name', 'Values': [prefix]}], NextToken=next_token)
        else:
            query_result = ssm.describe_parameters(Filters=[{'Key': 'Name', 'Values': [prefix]}])
        logging.debug("Query result %s" % str(query_result))
        if 'ResponseMetadata' in query_result:
            if 'HTTPStatusCode' in query_result['ResponseMetadata']:
                if query_result['ResponseMetadata']['HTTPStatusCode'] == 200:
                    if next_token is None:
                        #grab the parameter list on the first run or you'll lose it
                        parameter_list.extend(query_result['Parameters'])
                    if 'NextToken' in query_result:
                        logging.debug("Next token found")
                        parameter_list.extend(get_parameters_with_prefix(prefix, next_token=query_result['NextToken']))
                        logging.debug("Out of recursion")
                    else:
                        logging.debug("No next token, storing")
                        if next_token is not None:
                            parameter_list.extend(query_result['Parameters'])
        logging.debug("Parameter List %s" % parameter_list)
        return parameter_list


    # If aws_access_key and aws_secret_key provided, use those
    if aws_access_key is None:
        session = boto3.session.Session(region_name=aws_region)
    else:
        session = boto3.session.Session(aws_access_key_id=aws_access_key,
                                        aws_secret_access_key=aws_secret_key,
                                        region_name=aws_region)

    ssm = session.client('ssm')

    parameters_list = get_parameters_with_prefix(param_prefix, next_token=None)
    parameter_names_list = []
    for param in parameters_list:
        parameter_names_list.append(param['Name'])

    if parameter_names_list:
        # Make sure we have a temp dir to work with
        temp_dir = tempfile.gettempdir()
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        for param in get_parameters(parameter_names_list):
            parameter_name = param['Name']
            parameter_value = param['Value']
            process_parameter(parameter_name, parameter_value)


if __name__ == "__main__":

    LOG_FILENAME = 'parameter-sync.log'

    description =  "Script to get all parameters from AWS Parameter\n"
    description += "Store with a prefix that matches the given prefix\n\n"
    description += "Note: The following environment variables can be set prior to execution\n"
    description += "      of the script (or alternatively, set them using script parameters)\n\n"
    description += "      AWS_ACCESS_KEY_ID\n"
    description += "      AWS_SECRET_ACCESS_KEY"

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("--aws-access-key-id", help="AWS Access Key ID", dest='aws_access_key', required=False)
    parser.add_argument("--aws-secret-access-key", help="AWS Secret Access Key", dest='aws_secret_key', required=False)
    parser.add_argument("--aws-region", help="AWS Region", dest='aws_region', required=True)
    parser.add_argument("--param-prefix", help="Parameter prefix", dest='param_prefix', required=True)
    parser.add_argument("--credentials-path", help="Where credentials are stored", dest='cred_path', default='/credentials/')
    parser.add_argument("--verbose", help="Turn on DEBUG logging", action='store_true', required=False)
    parser.add_argument("--dryrun", help="Do a dryrun - no changes will be performed", dest='dryrun',
                        action='store_true', default=False,
                        required=False)
    args = parser.parse_args()

    log_level = logging.INFO

    if args.verbose:
        print('Verbose logging selected')
        log_level = logging.DEBUG

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # # create file handler which logs even debug messages
    # fh = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=5242880, backupCount=5)
    # fh.setLevel(logging.DEBUG)
    # create console handler using level set in log_level
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    console_formatter = logging.Formatter('%(levelname)8s: %(message)s')
    ch.setFormatter(console_formatter)
    # file_formatter = logging.Formatter('%(asctime)s - %(levelname)8s: %(message)s')
    # fh.setFormatter(file_formatter)
    # Add the handlers to the logger
    # logger.addHandler(fh)
    logger.addHandler(ch)

    if args.aws_access_key:
        aws_access_key = args.aws_access_key
    else:
        aws_access_key = None

    if args.aws_secret_key:
        aws_secret_key = args.aws_secret_key
    else:
        aws_secret_key = None

    logging.debug('INIT')
    logging.info('Getting parameters with prefix %s from AWS Parameter Store' % args.param_prefix)
    logging.info('Parameter values will be compared against file contents in "%s" and updated if necessary' % args.cred_path)
    process_parameters_with_prefix(args.param_prefix, args.cred_path, args.aws_region,
                                   aws_access_key, aws_secret_key, args.dryrun)
    logging.info('COMPLETE')
