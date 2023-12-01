# File: censys_view.py
#
# Copyright (c) 2016-2022 Splunk Inc.
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
from censys_consts import *


def _get_ctx_result(result):
    ctx_result = {}

    ctx_result["summary"] = result.get_summary()
    ctx_result["param"] = result.get_param()
    ctx_result["status"] = result.get_status()

    message = result.get_message()

    # if status is failure then add the message
    if not ctx_result["status"]:
        ctx_result["message"] = message

    if CENSYS_NO_INFO in message:
        ctx_result["message"] = message

    data = result.get_data()

    if not data:
        return ctx_result

    data = data[0]

    ctx_result["data"] = data

    return ctx_result


def display_cert_info(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)
    # print context
    return "cs_cert_info.html"


def display_ip_domain_info(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)
    # print context
    return "cs_ip_domain_info.html"
