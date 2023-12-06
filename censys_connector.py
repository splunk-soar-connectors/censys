# File: censys_connector.py
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
#
#
import json

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from censys_consts import *
from censys_rest import make_rest_call
from censys_search import CensysSearch
from censys_validation import is_ip


class CensysConnector(BaseConnector):
    def __init__(self):
        self._headers = {}
        self.search = CensysSearch(self.get_config())
        super().__init__()

    def _test_connectivity(self, param):
        """Test connectivity by retrieving a valid token"""

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Testing connectivity")

        ret_val, _ = make_rest_call(
            "/api/v1/account",
            action_result,
            self.get_config(),
            method="get",
        )

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.save_progress("Connectivity test failed")
            return action_result.set_status(
                phantom.APP_ERROR, "Connectivity test failed"
            )

        self.save_progress("Connectivity test passed")
        return action_result.set_status(phantom.APP_SUCCESS, "Connectivity test passed")

    def _handle_lookup(self, query, dataset, action_result):
        req_method, api = CENSYS_API_METHOD_MAP["info"]

        api_url = api.format(dataset=dataset, value=query)

        ret_val, response = make_rest_call(
            api_url,
            action_result,
            self.get_config(),
            method=req_method,
        )

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        self._process_ports(response)

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _process_ports(self, response):
        protocols = response.get("protocols")

        if not protocols:
            return response

        ports = [x.split("/")[0] for x in protocols]

        if not ports:
            return response

        response["ports"] = {}

        for port in ports:
            if port not in response:
                continue

            response["ports"].update({port: response[port]})
            del response[port]

        return response

    def _lookup_ip(self, param):
        self.debug_print("Entering _lookup_ip")

        action_result = self.add_action_result(ActionResult(param))
        summary_data = action_result.update_summary({})
        req_method, endpoint = CENSYS_API_METHOD_MAP["info"]
        ip = param[CENSYS_JSON_IP]
        if not is_ip(ip):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid value in the 'ip' action parameter",
            )
        ret_val, response = make_rest_call(
            endpoint.format(dataset=CENSYS_QUERY_HOSTS_DATASET, value=ip),
            action_result,
            self.get_config(),
            method=req_method,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get("result", {}).get("services"):
            return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)

        summary_data["port"] = (
            response.get("result", {}).get("services", [])[0].get("port")
        )
        summary_data["service_name"] = (
            response.get("result", {}).get("services", [])[0].get("service_name")
        )

        action_result.add_data(response)

        self._update_summary(action_result, response)

        self.debug_print("Exiting _lookup_ip")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _query_ip(self, param):
        self.debug_print("Entering _query_ip")

        action_result = self.add_action_result(ActionResult(param))
        summary_data = action_result.update_summary({})

        ret_val, response = self.search.query_dataset(
            action_result,
            summary_data,
            CENSYS_QUERY_HOSTS_DATASET,
            param,
            CENSYS_QUERY_IP_DATA_PER_PAGE,
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._update_summary(action_result, response)

        self.debug_print("Exiting _query_ip")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_certificate(self, param):
        self.debug_print("Entering _lookup_certificate")

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_lookup(
            param[CENSYS_JSON_SHA256], "certificates", action_result
        )

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if "do not know anything" in message:
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        # summary
        parsed = response.get("parsed", {})

        if parsed:
            summary = {}

            validity = parsed.get("validity")

            if validity:
                valid_from = validity.get("start")
                valid_to = validity.get("end")
                summary.update({"valid_from": valid_from, "valid_to": valid_to})

            summary.update(
                {
                    "issuer_dn": parsed.get("issuer_dn"),
                    "subject_dn": parsed.get("subject_dn"),
                }
            )

            action_result.update_summary(summary)

        self.debug_print("Exiting _lookup_certificate")

        return ret_val

    def _query_certificate(self, param):
        """Use handle_search to query the correct dataset with the query string"""

        self.debug_print("Entering _query_certificate")

        action_result = self.add_action_result(ActionResult(param))
        summary_data = action_result.update_summary({})

        ret_val, response = self.search.query_dataset(
            action_result,
            summary_data,
            CENSYS_QUERY_CERTIFICATE_DATASET,
            param,
            CENSYS_QUERY_CERTIFICATE_DATA_PER_PAGE,
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._update_summary(action_result, response)

        self.debug_print("Exiting _query_certificate")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_summary(self, action_result, response):
        protocols = response.get("protocols")

        if protocols:
            if not isinstance(protocols, list):
                protocols = [protocols]

            protocols = ", ".join(protocols)
            action_result.update_summary({"protocols": protocols})

        return action_result

    def _lookup_domain(self, param):
        self.debug_print("Entering _lookup_domain")

        action_result = self.add_action_result(ActionResult(param))

        self.debug_print("Exiting _lookup_domain")

        return action_result.set_status(
            phantom.APP_ERROR, "This action is not yet supported by Censys in API v2"
        )

    def _query_domain(self, param):
        """Use handle_search to query the correct dataset with the query string"""

        self.debug_print("Entering _query_domain")

        action_result = self.add_action_result(ActionResult(param))

        self.debug_print("Exiting _query_domain")

        return action_result.set_status(
            phantom.APP_ERROR, "This action is not yet supported by Censys in API v2"
        )

    def handle_action(self, param):
        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action == CENSYS_LOOKUP_IP_ACTION:
            ret_val = self._lookup_ip(param)
        elif action == CENSYS_LOOKUP_DOMAIN_ACTION:
            ret_val = self._lookup_domain(param)
        elif action == CENSYS_LOOKUP_CERTIFICATE_ACTION:
            ret_val = self._lookup_certificate(param)
        elif action == CENSYS_QUERY_IP_ACTION:
            ret_val = self._query_ip(param)
        elif action == CENSYS_QUERY_DOMAIN_ACTION:
            ret_val = self._query_domain(param)
        elif action == CENSYS_QUERY_CERTIFICATE_ACTION:
            ret_val = self._query_certificate(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {}

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self.set_validator("ipv6", is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=CENSYS_DEFAULT_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url,
                verify=verify,
                data=data,
                headers=headers,
                timeout=CENSYS_DEFAULT_TIMEOUT,
            )
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CensysConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
