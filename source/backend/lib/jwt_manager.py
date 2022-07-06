# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import jwt
from flask import request


class JwtManager:
    JWT_ALGORITHM = 'HS256'

    def __init__(self, token_secret):
        self.secret = token_secret

    def get_jwt_token(self, challenge_id):
        payload = {
            'challengeId': challenge_id
        }
        return jwt.encode(payload, self.secret, algorithm=JwtManager.JWT_ALGORITHM)

    def get_challenge_id(self, jwt_token):
        decoded = jwt.decode(jwt_token, self.secret, algorithms=JwtManager.JWT_ALGORITHM)
        return decoded['challengeId']
