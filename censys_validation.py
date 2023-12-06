# File: censys_validation.py
#
# Copyright (c) 2016-2023 Splunk Inc.
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
import ipaddress

import phantom.app as phantom

from censys_consts import CENSYS_ERR_MSG_UNAVAILABLE, CENSYS_INT_ERR_MSG


def parse_http_error(self, action_result, r):
    if "json" not in r.headers.get("Content-Type", ""):
        return ""

    try:
        resp_json = r.json()
    except Exception:
        return (
            action_result.set_status(
                phantom.APP_ERROR, "Unable to parse response as JSON"
            ),
            None,
        )

    message = "Server returned error with status: {}, Type: {}, Detail: {}".format(
        resp_json.get("status", "NA"),
        resp_json.get("error_type", "NA"),
        resp_json.get("error", "NA"),
    )

    return action_result.set_status(phantom.APP_ERROR, message)


def get_error_message_from_exception(self, e):
    """
    Get appropriate error message from the exception.
    :param e: Exception object
    :return: error message
    """

    error_code = None
    error_msg = CENSYS_ERR_MSG_UNAVAILABLE

    try:
        if hasattr(e, "args"):
            if len(e.args) > 1:
                error_code = e.args[0]
                error_msg = e.args[1]
            elif len(e.args) == 1:
                error_msg = e.args[0]
    except Exception:
        self.debug_print("Error occurred while fetching exception information")

    return f"Error Code: {error_code}. Error Message: {error_msg}" if error_code else f"Error Message: {error_msg}"


def validate_integer(action_result, parameter, key, allow_zero=False):
    try:
        if not float(parameter).is_integer():
            return (
                action_result.set_status(
                    phantom.APP_ERROR, CENSYS_INT_ERR_MSG.format(key=key)
                ),
                None,
            )

        parameter = int(parameter)
    except Exception:
        return (
            action_result.set_status(
                phantom.APP_ERROR, CENSYS_INT_ERR_MSG.format(key=key)
            ),
            None,
        )

    if parameter < 0:
        return (
            action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid non-negative integer value in the {}".format(
                    key
                ),
            ),
            None,
        )
    if not allow_zero and parameter == 0:
        return (
            action_result.set_status(
                phantom.APP_ERROR,
                f"Please provide a positive integer value in the {key}",
            ),
            None,
        )

    return phantom.APP_SUCCESS, parameter


def is_ip(input_ip_address):
    """
    Function that checks given address and return True if address is valid IPv4 or IPV6 address.

    :param input_ip_address: IP address
    :return: status (success/failure)
    """

    try:
        ipaddress.ip_address(input_ip_address)
    except ValueError:
        return False
    return True
