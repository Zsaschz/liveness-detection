import base64
import binascii
import imghdr
import decimal
import functools
import json
import os
import secrets
import boto3
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.jwt_manager import JwtManager
from importlib import import_module
from botocore import config
from botocore.exceptions import ClientError

# import app.logger

# logger = app.logger.getLogger(__name__)

from flask import Flask, request, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

STATE_NEXT = 1
STATE_CONTINUE = 0
CHALLENGE_FAIL = -1
CHALLENGE_SUCCESS = 2

_FAIL_STATE = '_FAIL_STATE'
_FIRST_STATE = '_FIRST_STATE'

_REGION_NAME = os.getenv('REGION_NAME')
_BUCKET_NAME = os.getenv('BUCKET_NAME')
_TABLE_NAME = os.getenv('TABLE_NAME')
_THREAD_POOL_SIZE = int(os.getenv('THREAD_POOL_SIZE', 10))

_MAX_IMAGE_SIZE = 15728640
_SEND_ANONYMOUS_USAGE_DATA = os.getenv('SEND_ANONYMOUS_USAGE_DATA', 'False').upper() == 'TRUE'

_extra_params = {}
if _SEND_ANONYMOUS_USAGE_DATA and 'SOLUTION_IDENTIFIER' in os.environ:
    _extra_params['user_agent_extra'] = os.environ['SOLUTION_IDENTIFIER']
config = config.Config(**_extra_params)

_s3 = boto3.client('s3', region_name=_REGION_NAME)
_rek = boto3.client('rekognition', region_name=_REGION_NAME)
_table = boto3.resource('dynamodb', region_name=_REGION_NAME).Table(_TABLE_NAME) if _TABLE_NAME else None

print(_s3, _rek, _table)

_challenge_types = []
_challenge_params_funcs = dict()
_challenge_state_funcs = dict()

_challenge_type_selector_func = [lambda client_metadata: secrets.choice(_challenge_types)]

_jwt_manager = JwtManager(os.getenv('TOKEN_SECRET'))


def challenge_type_selector(func):
    app.logger.debug('registering challenge_type_selector: %s', func.__name__)
    _challenge_type_selector_func[0] = func
    return func


def challenge_params(challenge_type):
    def decorator(func):
        if challenge_type not in _challenge_types:
            _challenge_types.append(challenge_type)
        _challenge_params_funcs[challenge_type] = func
        return func

    return decorator


def check_state_timeout(func, end_times, frame, timeout):
    frame_timestamp = frame['timestamp']
    if func.__name__ not in end_times:
        end_times[func.__name__] = frame_timestamp + timeout * 1000
    elif frame_timestamp > end_times[func.__name__]:
        app.logger.debug('State timed out: %s', frame_timestamp)
        raise _Fail


def run_state_processing_function(func, challenge, context, frame):
    try:
        res = func(challenge, frame, context)
    except Exception as e:
        app.logger.error('Exception: %s', e)
        raise e
    return res


def challenge_state(challenge_type, first=False, next_state=_FAIL_STATE, timeout=10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(challenge, frame, context, end_times):
            check_state_timeout(func, end_times, frame, timeout)
            res = run_state_processing_function(func, challenge, context, frame)
            app.logger.debug('res: %s', res)
            # Check result
            if res == STATE_CONTINUE:
                return wrapper
            if res == STATE_NEXT:
                return _challenge_state_funcs[challenge_type][next_state]
            if res == CHALLENGE_SUCCESS:
                raise _Success
            if res == CHALLENGE_FAIL:
                raise _Fail

        # Register challenge type (if not yet)
        if challenge_type not in _challenge_types:
            _challenge_types.append(challenge_type)
        # Create challenge type's state list with default fail state (if not yet)
        if challenge_type not in _challenge_state_funcs:
            _challenge_state_funcs[challenge_type] = dict()
            _challenge_state_funcs[challenge_type][_FAIL_STATE] = lambda: CHALLENGE_FAIL
        # Register state for challenge type
        _challenge_state_funcs[challenge_type][func.__name__] = wrapper
        # Register as fist state (if first is true)
        if first:
            _challenge_state_funcs[challenge_type][_FIRST_STATE] = wrapper
        return wrapper

    return decorator


class _Success(Exception):
    pass


class _Fail(Exception):
    pass


# def jwt_token_auth(func):
#     def inner(challenge_id):
#         app.logger.debug('Starting jwt_token_auth decorator')
#         try:
#             request = blueprint.current_request.json_body
#             token = request['token']
#             app.logger.debug(f'Authorization header (JWT): {token}')
#             jwt_challenge_id = _jwt_manager.get_challenge_id(token)
#             app.logger.debug(f'Authorization header challenge id: {jwt_challenge_id}')
#             app.logger.debug(f'Request challenge id: {challenge_id}')
#             if challenge_id != jwt_challenge_id:
#                 raise AssertionError()
#         except Exception:
#             app.logger.debug('Could not verify challenge id')
#             raise Exception("Unauthorized")
#         app.logger.debug('Challenge id successfully verified')
#         return func(challenge_id)

#     return inner


@app.post('/challenge')
def create_challenge():
    app.logger.debug('create_challenge')
    client_metadata = request.json
    # Validating client metadata input
    try:
        int(client_metadata['imageWidth'])
    except ValueError:
        print("value error image width")
        abort(401)
    try:
        int(client_metadata['imageHeight'])
    except ValueError:
        print("value error image height")
        abort(401)
    app.logger.debug('client_metadata: %s', client_metadata)
    # Saving challenge on DynamoDB table
    challenge = dict()
    challenge_id = str(uuid.uuid1())
    challenge['id'] = challenge_id
    challenge['token'] = _jwt_manager.get_jwt_token(challenge_id)
    challenge['type'] = _challenge_type_selector_func[0](client_metadata)
    challenge['params'] = _challenge_params_funcs[challenge['type']](client_metadata)
    app.logger.debug('challenge: %s', challenge)
    _table.put_item(Item=challenge)
    return challenge


# @jwt_token_auth
@app.put('/challenge/<challenge_id>/frame')
def put_challenge_frame(challenge_id):
    app.logger.debug('put_challenge_frame: %s', challenge_id)
    body = request.json
    # Validating timestamp input
    try:
        timestamp = int(body['timestamp'])
    except ValueError:
        abort(401)
    app.logger.debug('timestamp: %s', timestamp)
    # Validating frame input
    try:
        frame = base64.b64decode(body['frameBase64'], validate=True)
    except binascii.Error:
        abort(401)
    if len(frame) > _MAX_IMAGE_SIZE:
        abort(401)
    if imghdr.what(None, h=frame) != 'jpeg':
        abort(401)
    frame_key = '{}/{}.jpg'.format(challenge_id, timestamp)
    app.logger.debug('frame_key: %s', frame_key)
    # Updating challenge on DynamoDB table
    try:
        _table.update_item(
            Key={'id': challenge_id},
            UpdateExpression='set #frames = list_append(if_not_exists(#frames, :empty_list), :frame)',
            ExpressionAttributeNames={'#frames': 'frames'},
            ExpressionAttributeValues={
                ':empty_list': [],
                ':frame': [{
                    'timestamp': timestamp,
                    'key': frame_key
                }]
            },
            ReturnValues='NONE'
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'ConditionalCheckFailedException':
            app.logger.info('Challenge not found: %s', challenge_id)
            abort(401)
    # Uploading frame to S3 bucket
    _s3.put_object(
        Body=frame,
        Bucket=_BUCKET_NAME,
        Key=frame_key,
        ExpectedBucketOwner=os.getenv('ACCOUNT_ID')  # Bucket Sniping prevention
    )
    return {'message': 'Frame saved successfully'}


# @jwt_token_auth
@app.post('/challenge/<challenge_id>/verify')
def verify_challenge_response(challenge_id):
    app.logger.debug('verify_challenge_response: %s', challenge_id)
    # Looking up challenge on DynamoDB table
    item = _table.get_item(Key={'id': challenge_id})
    if 'Item' not in item:
        app.logger.info('Challenge not found: %s', challenge_id)
        abort(401)
    challenge = _read_item(item['Item'])
    app.logger.debug('challenge: %s', challenge)
    # Getting challenge type, params and frames
    challenge_type = challenge['type']
    params = challenge['params']
    frames = challenge['frames']
    # Invoking Rekognition with parallel threads
    with ThreadPoolExecutor(max_workers=_THREAD_POOL_SIZE) as pool:
        futures = [
            pool.submit(
                _detect_faces, frame
            ) for frame in frames
        ]
        frames = [r.result() for r in as_completed(futures)]
    frames.sort(key=lambda frame: frame['key'])
    current_state = _challenge_state_funcs[challenge_type][_FIRST_STATE]
    context = dict()
    end_times = dict()
    success = False
    for frame in frames:
        try:
            while True:
                app.logger.debug('----------------')
                app.logger.debug('current_state: %s', current_state.__name__)
                app.logger.debug('frame[timestamp]: %s', frame['timestamp'])
                app.logger.debug('context.keys: %s', context.keys())
                app.logger.debug('end_times: %s', end_times)
                next_state = current_state(params, frame, context, end_times)
                if next_state.__name__ != current_state.__name__:
                    current_state = next_state
                    app.logger.debug('NEXT')
                else:
                    app.logger.debug('CONTINUE')
                    break
        except _Success:
            success = True
            break
        except _Fail:
            break
    # Returning result based on final state
    app.logger.debug('success: %s', success)
    response = {'success': success}
    app.logger.debug('response: %s', response)
    # Updating challenge on DynamoDB table
    _table.update_item(
        Key={'id': challenge_id},
        UpdateExpression='set #frames = :frames, #success = :success',
        ExpressionAttributeNames={
            '#frames': 'frames',
            '#success': 'success'
        },
        ExpressionAttributeValues={
            ':frames': _write_item(frames),
            ':success': response['success']
        },
        ReturnValues='NONE'
    )
    return response


def _detect_faces(frame):
    frame['rekMetadata'] = _rek.detect_faces(
        Attributes=['ALL'],
        Image={
            'S3Object': {
                'Bucket': _BUCKET_NAME,
                'Name': frame['key']
            }
        }
    )['FaceDetails']
    return frame


def _read_item(item):
    return json.loads(json.dumps(item, cls=_DecimalEncoder))


def _write_item(item):
    return json.loads(json.dumps(item), parse_float=decimal.Decimal)


# Helper class to convert a DynamoDB item to JSON.
class _DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            return int(o)
        return super(_DecimalEncoder, self).default(o)

CLIENT_CHALLENGE_SELECTION = os.getenv('CLIENT_CHALLENGE_SELECTION', "False").upper() == 'TRUE'

@challenge_type_selector
def random_challenge_selector(client_metadata):
    app.logger.debug('random_challenge_selector')
    if CLIENT_CHALLENGE_SELECTION and 'challengeType' in client_metadata:
        return client_metadata['challengeType']
    return secrets.choice(['POSE', 'NOSE'])


import_module('lib.challenges.nose')
import_module('lib.challenges.pose')
import_module('lib.challenges.custom')