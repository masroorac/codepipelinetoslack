'''
Example input from CodePipeline:

{
    "CodePipeline.job": {
        "id": "11111111-abcd-1111-abcd-111111abcdef",
        "accountId": "111111111111",
        "data": {
            "actionConfiguration": {
                "configuration": {
                    "FunctionName": "MyLambdaFunctionForAWSCodePipeline",
                    "UserParameters": "some-input-such-as-a-URL"
                }
            },
            "inputArtifacts": [
                {
                    "location": {
                        "s3Location": {
                            "bucketName": "codepipeline bucket",
                            "objectKey": "application name"
                        },
                        "type": "S3"
                    },
                    "revision": null,
                    "name": "ArtifactName"
                }
            ],
            "outputArtifacts": [],
            "artifactCredentials": {
                "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "sessionToken": "MIICiTCCAfICCQD6m7oRw0uXOjANBgkqhkiG9w
0BAQUFADCBiDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZ
WF0dGxlMQ8wDQYDVQQKEwZBbWF6b24xFDASBgNVBAsTC0lBTSBDb25zb2xlMRIw
EAYDVQQDEwlUZXN0Q2lsYWMxHzAdBgkqhkiG9w0BCQEWEG5vb25lQGFtYXpvbi5
jb20wHhcNMTEwNDI1MjA0NTIxWhcNMTIwNDI0MjA0NTIxWjCBiDELMAkGA1UEBh
MCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZBb
WF6b24xFDASBgNVBAsTC0lBTSBDb25zb2xlMRIwEAYDVQQDEwlUZXN0Q2lsYWMx
HzAdBgkqhkiG9w0BCQEWEG5vb25lQGFtYXpvbi5jb20wgZ8wDQYJKoZIhvcNAQE
BBQADgY0AMIGJAoGBAMaK0dn+a4GmWIWJ21uUSfwfEvySWtC2XADZ4nB+BLYgVI
k60CpiwsZ3G93vUEIO3IyNoH/f0wYK8m9TrDHudUZg3qX4waLG5M43q7Wgc/MbQ
ITxOUSQv7c7ugFFDzQGBzZswY6786m86gpEIbb3OhjZnzcvQAaRHhdlQWIMm2nr
AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAtCu4nUhVVxYUntneD9+h8Mg9q6q+auN
KyExzyLwaxlAoo7TJHidbtS4J5iNmZgXL0FkbFFBjvSfpJIlJ00zbhNYS5f6Guo
EDmFJl0ZxBHjJnyp378OD8uTs7fLvjx79LjSTbNYiytVbZPQUQ5Yaxu2jXnimvw
3rrszlaEXAMPLE=",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
            },
            "continuationToken": "A continuation token if continuing job"
        }
    }
}
'''

import boto3
import json
import logging
import os

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# The base-64 encoded, encrypted key (CiphertextBlob)
# stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to,
# stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slackChannel']

kms = boto3.client('kms')
code_pipeline = boto3.client('codepipeline')

ctb = b64decode(ENCRYPTED_HOOK_URL)
domain = kms.decrypt(CiphertextBlob=ctb)['Plaintext']
HOOK_URL = "https://" + domain.decode('utf-8')

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def put_job_success(job, message):
    """Notify CodePipeline of a successful job

    Args:
        job: The CodePipeline job ID
        message: A message to be logged relating to the job status

    Raises:
        Exception: Any exception thrown by .put_job_success_result()

    """
    print('Putting job success')
    print(message)
    code_pipeline.put_job_success_result(jobId=job)


def put_job_failure(job, message):
    """Notify CodePipeline of a failed job

    Args:
        job: The CodePipeline job ID
        message: A message to be logged relating to the job status

    Raises:
        Exception: Any exception thrown by .put_job_failure_result()

    """
    print('Putting job failure')
    print(message)
    fd = {'message': message, 'type': 'JobFailed'}
    code_pipeline.put_job_failure_result(jobId=job, failureDetails=fd)


def continue_job_later(job, message):
    """Notify CodePipeline of a continuing job

    This will cause CodePipeline to invoke the function again with the
    supplied continuation token.

    Args:
        job: The JobID
        message: A message to be logged relating to the job status
        continuation_token: The continuation token

    Raises:
        Exception: Any exception thrown by .put_job_success_result()

    """

    # Use the continuation token to keep track of any job execution state
    # This data will be available when a new job
    # is scheduled to continue the current execution
    ct = json.dumps({'previous_job_id': job})

    print('Putting job continuation')
    print(message)
    code_pipeline.put_job_success_result(jobId=job, continuationToken=ct)


def send_slack_message(message):
    binary_data = json.dumps(message).encode('utf-8')
    req = Request(HOOK_URL, binary_data)
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


def get_error_message(job, pipeline, action):
    response = code_pipeline.get_pipeline_state(name=pipeline)
    action_found = False
    for s in response['stageStates']:
        for a in s['actionStates']:
            if a['actionName'] == action:
                action_found = True
                error = a['latestExecution']['errorDetails']['message']
                return error
    if not action_found:
        message = "Action {} not found".format(action)
        put_job_failure(job, message)


def check_action_status(job, pipeline, action):
    response = code_pipeline.get_pipeline_state(name=pipeline)
    action_found = False
    for s in response['stageStates']:
        for a in s['actionStates']:
            if a['actionName'] == action:
                action_found = True
                status = a['latestExecution']['status']
                return status
    if not action_found:
        message = "Action {} not found".format(action)
        put_job_failure(job, message)


def get_pipeline_name(job_id):
    print('Getting job details')
    response = code_pipeline.get_job_details(jobId=job_id)
    return response['jobDetails']['data']['pipelineContext']['pipelineName']


def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    job_id = event['CodePipeline.job']['id']
    job_data = event['CodePipeline.job']['data']
    configuration = job_data['actionConfiguration']['configuration']
    user_parameters = configuration['UserParameters']
    # function_name = configuration['FunctionName']
    pipeline_name = get_pipeline_name(job_id)

    status = check_action_status(job_id, pipeline_name, user_parameters)

    message = "{}: {} - {}".format(pipeline_name, user_parameters, status)
    logger.info("Message: " + message)

    if status == 'InProgress':
        continue_job_later(job_id, message)
        # we send the "InProgress" message only once
        if 'continuationToken' in job_data:
            return 'Complete. Will continue job later.'

    items = [{'color': 'good', 'text': message}]
    if status == 'Failed':
        items = [{'color': 'danger', 'text': message}]

    slack_message = {
        'channel': SLACK_CHANNEL,
        'attachments': items
    }

    send_slack_message(slack_message)

    # we also send a Slack notification with the error
    if status == 'Failed':
        error = get_error_message(job_id, pipeline_name, user_parameters)
        error_message = "Error: {}".format(error)

        items = [{'color': 'danger', 'text': error_message}]
        slack_message_error = {
            'channel': SLACK_CHANNEL,
            'attachments': items
        }
        send_slack_message(slack_message_error)

    # we don't fail even if the message wasn't sent
    # as we don't want the pipeline to stop
    put_job_success(job_id, 'Function ran successfully')

    return 'Complete.'
