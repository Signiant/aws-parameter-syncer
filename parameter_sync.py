import argparse
import hashlib
import logging
import os
import shutil
import tempfile
import boto3
import sys

#setup logging
FORMAT = '%(asctime)-15s [%(levelname)s] %(message)s'
logging.basicConfig(format=FORMAT, stream=sys.stdout, level=logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)


def get_sha256_hash(file_path):
    logger.debug(f'Hashing "{file_path}" using SHA256')
    BUF_SIZE = 65536  # let's read stuff in 64kb chunks!
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    logger.debug('   SHA256 hash: {0}'.format(sha256.hexdigest()))
    return sha256.digest()


def process_parameters_with_prefix(param_prefix, cred_path, aws_region, aws_access_key=None, aws_secret_key=None, dryrun=False):
    logger.debug(f'Searching for parameters with a prefix of {param_prefix}')

    def get_parameters(parameter_names_list):
        parameter_list = []
        if parameter_names_list:
            for parameter_name in parameter_names_list:
                result = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
                if result:
                    if 'ResponseMetadata' in result:
                        if 'HTTPStatusCode' in result['ResponseMetadata']:
                            if result['ResponseMetadata']['HTTPStatusCode'] == 200:
                                if 'Parameter' in result:
                                    parameter_list.append(result['Parameter'])
        return parameter_list

    def process_parameter(param_name, param_value):
        filename = param_name.split(param_prefix)[1]
        full_cred_path = cred_path + os.sep + filename
        existing_file_sha256_hash = None
        if os.path.exists(full_cred_path):
            existing_file_sha256_hash = get_sha256_hash(full_cred_path)
        new_file_full_path = temp_dir + os.sep + filename + '.new'
        logger.debug(f'Storing retrieved value for parameter "{param_name}" in "{new_file_full_path}"')
        with open(new_file_full_path, 'w') as f:
            f.write(param_value)
        new_file_sha256_hash = get_sha256_hash(new_file_full_path)
        logger.debug('Comparing file hashes')
        if existing_file_sha256_hash != new_file_sha256_hash:
            if not existing_file_sha256_hash:
                logger.info(f'This is a new credentials file: "{filename}"')
            else:
                logger.info(f"Contents don't match - replacing \"{full_cred_path}\" contents with value from parameter store")
            if not dryrun:
                if os.path.exists(new_file_full_path) and os.stat(new_file_full_path).st_size > 0:
                    shutil.copyfile(new_file_full_path, full_cred_path)
                else:
                    logger.error(f'file {new_file_full_path} is missing or zero length - NOT replacing')
            else:
                logger.info(f'*** Dryrun selected - will NOT update "{full_cred_path}"')
        else:
            logger.info(f'Contents of existing "{full_cred_path}" MATCH with value for "{param_name}" from parameter store')

        # Cleanup
        if new_file_full_path:
            logger.debug(f'Removing {new_file_full_path}')
            os.remove(new_file_full_path)

    def get_parameters_with_prefix(prefix, next_token=None):
        parameter_list = []
        if next_token:
            query_result = ssm.describe_parameters(Filters=[{'Key': 'Name', 'Values': [prefix]}], NextToken=next_token)
        else:
            query_result = ssm.describe_parameters(Filters=[{'Key': 'Name', 'Values': [prefix]}])
        logger.debug(f"Query result {str(query_result)}")
        if 'ResponseMetadata' in query_result:
            if 'HTTPStatusCode' in query_result['ResponseMetadata']:
                if query_result['ResponseMetadata']['HTTPStatusCode'] == 200:
                    if next_token is None:
                        #grab the parameter list on the first run or you'll lose it
                        parameter_list.extend(query_result['Parameters'])
                    if 'NextToken' in query_result:
                        logger.debug("Next token found")
                        parameter_list.extend(get_parameters_with_prefix(prefix, next_token=query_result['NextToken']))
                        parameter_list.extend(query_result['Parameters'])
                        logger.debug("Out of recursion")
                    else:
                        logger.debug("No next token, storing")
                        parameter_list.extend(query_result['Parameters'])
        logger.debug(f"Parameter List {parameter_list}")
        return parameter_list


    # If aws_access_key and aws_secret_key provided, use those
    if aws_access_key and aws_secret_key:
        session = boto3.session.Session(aws_access_key_id=aws_access_key,
                                        aws_secret_access_key=aws_secret_key,
                                        region_name=aws_region)
    else:
        session = boto3.session.Session(region_name=aws_region)

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


def create_aws_cred_file(key_id, secret, file_location, cred_filename, profile_name, aws_region):
    file_path = f'{file_location}{os.sep}{cred_filename}'
    if os.path.exists(file_path):
        # File already exists - append to it
        with open(file_path, 'a') as cred_file:
            cred_file.write('\n')
            cred_file.write(f'[{profile_name}]\n')
            if aws_region:
                cred_file.write(f'region={aws_region}\n')
            cred_file.write(f'aws_access_key_id={key_id}\n')
            cred_file.write(f'aws_secret_access_key={secret}\n')
    else:
        with open(file_path, 'w') as cred_file:
            cred_file.write(f'[{profile_name}]\n')
            if aws_region:
                cred_file.write(f'region={aws_region}\n')
            cred_file.write(f'aws_access_key_id={key_id}\n')
            cred_file.write(f'aws_secret_access_key={secret}\n')
    return file_path


def write_aws_cli_creds(key_id, secret, base_cred_path, aws_cred_list):
    aws_creds_tuples = []
    have_all_info = False
    for i, val in enumerate(aws_cred_list):
        if (i % 3) == 0:
            logging.debug(f'save-aws-creds - filename: {val}')
            filename = val
        elif (i % 3) == 1:
            logging.debug(f'save-aws-creds - profile name: {val}')
            if '#' in val:
                profile = val.replace('#', ' ')
            else:
                profile = val
        else:
            logging.debug(f'save-aws-creds - region: {val}')
            if 'none' in val.lower():
                region = None
            else:
                region = val
            have_all_info = True

        if have_all_info:
            aws_creds_tuples.append((filename, profile, region))
            have_all_info = False

    if len(aws_creds_tuples) > 0:
        logging.debug('Provided with the following tuples:')
        logging.debug(f'{aws_creds_tuples}')

        # write to a tmp file first
        temp_dir = tempfile.gettempdir()
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        aws_cred_files = []
        for f, p, r in aws_creds_tuples:
            tmp_cred_filepath = create_aws_cred_file(key_id, secret, temp_dir, f, p, r)
            if tmp_cred_filepath not in aws_cred_files:
                aws_cred_files.append(tmp_cred_filepath)

        # Now copy the tmp files to the base_cred_path
        for cred_file in aws_cred_files:
            filename = cred_file.split(os.sep)[-1]
            new_file_path = f"{base_cred_path}{os.sep}{filename}"
            logger.info(f'Saving AWS Credentials to {new_file_path}')
            shutil.copyfile(cred_file, new_file_path)
            # Cleanup
            logger.debug(f'Removing {cred_file}')
            os.remove(cred_file)


if __name__ == "__main__":

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
    parser.add_argument("--save-aws-creds", help="Save AWS Creds [filename, profile]", nargs='*')
    parser.add_argument("--dryrun", help="Do a dryrun - no changes will be performed", dest='dryrun',
                        action='store_true', default=False,
                        required=False)
    args = parser.parse_args()

    if args.verbose:
        print('Verbose logger selected')
        logger.setLevel(logging.DEBUG)

    if not os.environ.get('AWS_ACCESS_KEY_ID') and not args.aws_access_key:
        logger.critical('AWS Access Key Id not set - cannot continue')

    if not os.environ.get('AWS_SECRET_ACCESS_KEY') and not args.aws_secret_key:
        logger.critical('AWS Secret Access Key not set - cannot continue')

    logger.debug('INIT')
    logger.info(f'Getting parameters with prefix {args.param_prefix} from AWS Parameter Store')
    logger.info(f'Parameter values will be compared against file contents in "{args.cred_path}" and updated if necessary')
    process_parameters_with_prefix(args.param_prefix, args.cred_path, args.aws_region,
                                   args.aws_access_key, args.aws_secret_key, args.dryrun)

    if args.save_aws_creds:
        if args.aws_access_key and args.aws_secret_key:
            aws_access_key = args.aws_access_key
            aws_secret_key = args.aws_secret_key
        else:
            aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
            aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

        if len(args.save_aws_creds) % 3 != 0:
            logging.critical('Must provide filename, profile_name and region for aws creds')
            sys.exit(1)

        result = write_aws_cli_creds(aws_access_key, aws_secret_key, args.cred_path, args.save_aws_creds)

    logger.info('COMPLETE')
