This Lambda function has been created as AWS CodePipeline currently doesn't 
allow to send notifications to report the status of the pipeline. Hopefully 
this feature will be available in the future. 

The Lambda function is executed again and again (using the continuation token),
until the action it is monitoring succeded or failed. The fact that it is 
monitoring makes the entire pipeline slower (about 1 minute per monitored 
action) compared to a Lambda script that would just send a simple notification.

![Example - Slack screenshot](screenshot.png?raw=true "Example")

## How to use

### Lambda

Create a Lambda function using the code provided and the Python 3.6 runtime. 
Attach an IAM role that has at least the AWSLambdaBasicExecutionRole policy 
as well as this CodePipeline permissions: 

 - "codepipeline:PutJobSuccessResult"
 - "codepipeline:PutJobFailureResult"
 - "codepipeline:Get*"

### Slack

Create a Slack incoming webhook. 

Lambda environment variable name: kmsEncryptedHookUrl 
Get the webhook url (without the https://) and add it to the Lambda function
as an encrypted environment variable. 

Lambda environment variable name: slackChannel
Also add the Slack channel name you want to send the notifications to as an 
environment variable (no encryption).

### CodePipeline

Add an Invoke action in parallel to the action you want to monitor. 
Choose AWS Lambda as the Provider and select your Lambda function.
**Enter the name of the action you want to monitor as User Parameters.**
