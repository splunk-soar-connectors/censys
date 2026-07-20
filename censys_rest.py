# File: censys_rest.py
#
# Copyright (c) 2016-2026 Splunk Inc.
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

from censys_consts import CENSYS_API_URL, CENSYS_DEFAULT_TIMEOUT, CENSYS_ERR_JSON_DECODE, CENSYS_JSON_API_ID, CENSYS_JSON_SECRET
from censys_validation import get_error_message_from_exception


SENSITIVE_HTTP_HEADERS = {
    "authorization",
    "cookie",
    "proxy_authorization",
    "set_cookie",
    "www_authenticate",
}


def redact_sensitive_headers(value, inside_headers=False):
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            normalized_key = str(key).casefold().replace("-", "_")
            if inside_headers and normalized_key in SENSITIVE_HTTP_HEADERS:
                continue
            cleaned[key] = redact_sensitive_headers(child, inside_headers or normalized_key == "headers")
        return cleaned
    if isinstance(value, list):
        return [redact_sensitive_headers(item, inside_headers) for item in value]
    return value


def make_rest_call(endpoint, action_result, config, data=None, method="post"):
    request_func = getattr(requests, method)
    headers = {"Content-type": "application/json", "Accept": "text/plain"}

    try:
        response = request_func(
            f"{CENSYS_API_URL}{endpoint}",
            json=data,
            auth=(config[CENSYS_JSON_API_ID], config[CENSYS_JSON_SECRET]),
            headers=headers,
            timeout=CENSYS_DEFAULT_TIMEOUT,
        )
    except Exception as e:
        return (
            action_result.set_status(
                phantom.APP_ERROR,
                f"Unable to connect to the server. {get_error_message_from_exception(e)}",
            ),
            {},
        )

    if response.status_code == 429:
        return action_result.set_status(phantom.APP_ERROR, "Censys rate limit exceeded; retry later"), {}

    if response.status_code != 200:
        return parse_http_error(action_result, response), {}

    try:
        resp_json = response.json()
    except Exception as e:
        return (
            action_result.set_status(phantom.APP_ERROR, CENSYS_ERR_JSON_DECODE.format(e)),
            {},
        )

    api_code = resp_json.get("code")
    if resp_json.get("status") == "error" or resp_json.get("error") or (isinstance(api_code, int) and not 200 <= api_code < 300):
        return parse_http_error(action_result, response), {}

    return phantom.APP_SUCCESS, redact_sensitive_headers(resp_json)


def parse_http_error(action_result, r):
    if "json" not in r.headers.get("Content-Type", ""):
        return action_result.set_status(phantom.APP_ERROR, f"Censys returned HTTP status {r.status_code}")

    try:
        resp_json = r.json()
    except Exception as e:
        return (
            action_result.set_status(phantom.APP_ERROR, CENSYS_ERR_JSON_DECODE.format(e)),
            None,
        )

    message = "Server returned error with status: {}, Type: {}, Detail: {}".format(
        resp_json.get("code", resp_json.get("status", r.status_code)),
        resp_json.get("error_type", "NA"),
        resp_json.get("error", resp_json.get("detail", resp_json.get("message", "NA"))),
    )

    return action_result.set_status(phantom.APP_ERROR, message)
