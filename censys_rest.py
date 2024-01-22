# File: censys_rest.py
#
# Copyright (c) 2016-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
import phantom.app as phantom
import requests

from censys_consts import CENSYS_API_URL, CENSYS_ERR_JSON_DECODE, CENSYS_JSON_API_ID, CENSYS_JSON_SECRET
from censys_validation import get_error_message_from_exception


def make_rest_call(endpoint, action_result, config, data=None, method="post"):
    request_func = getattr(requests, method)
    headers = {"Content-type": "application/json", "Accept": "text/plain"}

    try:
        response = request_func(
            f"{CENSYS_API_URL}{endpoint}",
            json=data,
            auth=(config[CENSYS_JSON_API_ID], config[CENSYS_JSON_SECRET]),
            headers=headers,
        )
    except Exception as e:
        return (
            action_result.set_status(
                phantom.APP_ERROR,
                "Unable to connect to the server. {}".format(
                    get_error_message_from_exception(e)
                ),
            ),
            {},
        )

    if response.status_code not in (200, 429):
        return parse_http_error(action_result, response), {}

    try:
        resp_json = response.json()
    except Exception as e:
        return (
            action_result.set_status(
                phantom.APP_ERROR, CENSYS_ERR_JSON_DECODE.format(e, response.text)
            ),
            {},
        )

    if resp_json.get("status", "") == "error":
        return parse_http_error(action_result, response), {}

    return phantom.APP_SUCCESS, resp_json


def parse_http_error(action_result, r):
    if "json" not in r.headers.get("Content-Type", ""):
        return ""

    try:
        resp_json = r.json()
    except Exception as e:
        return (
            action_result.set_status(
                phantom.APP_ERROR, CENSYS_ERR_JSON_DECODE.format(e, r.text)
            ),
            None,
        )

    message = "Server returned error with status: {}, Type: {}, Detail: {}".format(
        resp_json.get("status", "NA"),
        resp_json.get("error_type", "NA"),
        resp_json.get("error", "NA"),
    )

    return action_result.set_status(phantom.APP_ERROR, message)
