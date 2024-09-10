import boto3
import json
import base64
import os
import logging
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from aws_lambda_powertools import Logger, Tracer, Metrics
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.utilities.data_classes import APIGatewayProxyEvent

# Initialize AWS Lambda Powertools
logger = Logger()
tracer = Tracer()
metrics = Metrics()

# Initialize the S3 client
s3_client = boto3.client('s3')

# Constants
BUCKET_NAME = os.environ['BUCKET_NAME']
SECRET_NAME = os.environ['PRIVATE_KEY_SECRET_NAME']

# Initialize Secrets Manager client
secrets_client = boto3.client('secretsmanager')

def get_private_key():
    try:
        secret_value = secrets_client.get_secret_value(SecretId=SECRET_NAME)
        return secret_value['SecretString']
    except ClientError as e:
        logger.error(f"Failed to retrieve private key: {str(e)}")
        raise

@tracer.capture_method
def sign_challenge(challenge, private_key_pem):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        signature = private_key.sign(
            challenge.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        logger.error(f"Failed to sign challenge: {str(e)}")
        raise

@tracer.capture_method
def generate_presigned_url(file_key):
    try:
        return s3_client.generate_presigned_url('get_object',
                                                Params={'Bucket': BUCKET_NAME,
                                                        'Key': file_key},
                                                ExpiresIn=3600)
    except ClientError as e:
        logger.error(f"Failed to generate pre-signed URL: {str(e)}")
        raise

@logger.inject_lambda_context(log_event=True)
@tracer.capture_lambda_handler
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: APIGatewayProxyEvent, context: LambdaContext):
    try:
        body = json.loads(event.body)
        file_key = body['file_key']
        challenge = body['challenge']
    except (KeyError, json.JSONDecodeError) as e:
        logger.error(f"Invalid request body: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid request body'})
        }

    try:
        private_key_pem = get_private_key()
        signature = sign_challenge(challenge, private_key_pem)
        url = generate_presigned_url(file_key)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'download_url': url,
                'signature': base64.b64encode(signature).decode()
            })
        }
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }

if __name__ == "__main__":
    # For local testing
    test_event = {
        'body': json.dumps({
            'file_key': 'test.txt',
            'challenge': base64.b64encode(os.urandom(32)).decode()
        })
    }
    print(lambda_handler(APIGatewayProxyEvent(test_event), LambdaContext()))
