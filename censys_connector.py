# File: censys_connector.py
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
#
#
import ipaddress
import json
import math
import time

import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from censys_consts import *


class CensysConnector(BaseConnector):

    ACTION_LOOKUP_IP = "lookup_ip"
    ACTION_LOOKUP_CERTIFICATE = "lookup_certificate"
    ACTION_LOOKUP_DOMAIN = "lookup_domain"
    ACTION_QUERY_IP = "query_ip"
    ACTION_QUERY_CERTIFICATE = "query_certificate"
    ACTION_QUERY_DOMAIN = "query_domain"

    def __init__(self):
        self._headers = {}
        super(CensysConnector, self).__init__()
        return

    def _parse_http_error(self, action_result, r):

        if 'json' not in r.headers.get('Content-Type', ''):
            return ""

        try:
            resp_json = r.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON"), None)

        message = "Server returned error with status: {0}, Type: {1}, Detail: {2}".format(
                resp_json.get('status', 'NA'), resp_json.get('error_type', 'NA'), resp_json.get('error', 'NA'))

        return action_result.set_status(phantom.APP_ERROR, message)

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error messages from the exception.
        :param e: Exception object
        :return: error message
        """

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = CENSYS_ERR_CODE_MSG
                    error_msg = e.args[0]
            else:
                error_code = CENSYS_ERR_CODE_MSG
                error_msg = CENSYS_ERR_MSG_UNAVAILABLE
        except:
            error_code = CENSYS_ERR_CODE_MSG
            error_msg = CENSYS_ERR_MSG_UNAVAILABLE

        try:
            if error_code in CENSYS_ERR_CODE_MSG:
                error_text = "Error Message: {0}".format(error_msg)
            else:
                error_text = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        except:
            self.debug_print("Error occurred while parsing error message")
            error_text = CENSYS_PARSE_ERR_MSG

        return error_text

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        try:
            if not float(parameter).is_integer():
                return action_result.set_status(phantom.APP_ERROR, CENSYS_INT_ERR_MSG.format(key=key)), None

            parameter = int(parameter)
        except:
            return action_result.set_status(phantom.APP_ERROR, CENSYS_INT_ERR_MSG.format(key=key)), None

        if parameter < 0:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {}".format(key)), None
        if not allow_zero and parameter == 0:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a positive integer value in the {}".format(key)), None

        return phantom.APP_SUCCESS, parameter

    def _is_ip(self, input_ip_address):
        """
        Function that checks given address and return True if address is valid IPv4 or IPV6 address.
        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        try:
            ipaddress.ip_address(input_ip_address)
        except Exception:
            return False
        return True

    def _make_rest_call(self, endpoint, action_result, data=None, method="post"):

        resp_json = None

        config = self.get_config()
        request_func = getattr(requests, method)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        try:
            response = request_func("{}{}".format(CENSYS_API_URL, endpoint), json=data,
                    auth=(config[CENSYS_JSON_API_ID], config[CENSYS_JSON_SECRET]), headers=headers)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to connect to the server. {}".format(
                self._get_error_message_from_exception(e))), resp_json)

        if response.status_code not in (200, 429):
            return (self._parse_http_error(action_result, response), {})

        try:
            resp_json = response.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON"), None)

        if resp_json.get('status', '') == 'error':
            return (self._parse_http_error(action_result, response), {})

        return (phantom.APP_SUCCESS, resp_json)

    def _test_connectivity(self, param):
        """ Test connectivity by retrieving a valid token
        """

        action_result = ActionResult()
        self.save_progress("Testing connectivity")

        ret_val, response = self._make_rest_call('/api/v1/account', action_result=action_result, method='get')

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.save_progress("Connectivity test failed")
            return self.set_status(phantom.APP_ERROR,)

        self.save_progress("Connectivity test passed")
        return self.set_status(phantom.APP_SUCCESS, "Connectivity test passed")

    def _check_datapath(self, datadict):
        for i in list(datadict.keys()):
            if "." in i:
                datadict[i.replace(".", "_")] = datadict[i]
                del(datadict[i])
        return datadict

    def _handle_search(self, query_string, censys_io_dataset, action_result, limit=None):
        """ Search Censys using the given query string in the Censys search language. censys_io_dataset specifies
            which type of data you are searching. At the time of writing there are 3 datasets: certificates,
            ipv4hosts, and websites (domains).
        """

        req_method, api = CENSYS_API_METHOD_MAP.get("search")
        data = {"query": query_string}

        ret_val, response = self._make_rest_call("{}{}".format(api, censys_io_dataset), action_result, data=data, method=req_method)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), action_result.get_message())

        num_pages = response.get('metadata', {}).get('pages', None)
        if num_pages is None:
            return (action_result.set_status(phantom.APP_ERROR), None)

        results = response.get("results", [])
        if limit:
            num_pages = min(math.ceil(limit / CENSYS_QUERY_CERTIFICATE_DATA_PER_PAGE), num_pages)
            for result in range(0, min(limit, CENSYS_QUERY_CERTIFICATE_DATA_PER_PAGE, len(results))):
                action_result.add_data(self._check_datapath(results[result]))
        else:
            for res in results:
                action_result.add_data(self._check_datapath(res))
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        config = self.get_config()
        auth = (config[CENSYS_JSON_API_ID], config[CENSYS_JSON_SECRET])
        for page in range(2, num_pages + 1):
            self.debug_print("requesting page {} out of {}".format(page, num_pages))
            data['page'] = page
            page_response = requests.post("{}{}{}".format(
                CENSYS_API_URL, api, censys_io_dataset), data=json.dumps(data), headers=headers, auth=auth, timeout=CENSYS_DEFAULT_TIMEOUT)
            if page_response.status_code != 200:
                self.debug_print("received {} response with body {}".format(page_response.status_code, page_response.text))
                return action_result.set_status(phantom.APP_SUCCESS), response

            response_json = page_response.json()

            results = response_json.get("results", [])
            if limit and page == num_pages and (limit % CENSYS_QUERY_CERTIFICATE_DATA_PER_PAGE ) != 0:
                for result in range(0, min(limit % CENSYS_QUERY_CERTIFICATE_DATA_PER_PAGE, len(results))):
                    action_result.add_data(self._check_datapath(results[result]))
            else:
                for result in results:
                    action_result.add_data(self._check_datapath(result))

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return (action_result.set_status(phantom.APP_SUCCESS), response)

    def _handle_view(self, query_string, search_action, action_result):

        req_method, api = CENSYS_API_METHOD_MAP.get("view")

        api = api.format(search_action, query_string)

        ret_val, response = self._make_rest_call(api, action_result, method=req_method)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        self._process_ports(response)

        action_result.add_data(response)

        return (action_result.set_status(phantom.APP_SUCCESS), response)

    def _process_ports(self, response):

        protocols = response.get('protocols')

        if (not protocols):
            return response

        ports = [x.split('/')[0] for x in protocols]

        if (not ports):
            return response

        response['ports'] = {}

        for port in ports:
            if (port not in response):
                continue

            response['ports'].update({port: response[port]})
            del response[port]

        return response

    def _lookup_ip(self, param):

        self.debug_print("Entering _lookup_ip")

        action_result = self.add_action_result(ActionResult(param))
        summary_data = action_result.update_summary({})
        req_method, endpoint = CENSYS_API_METHOD_MAP.get("hosts")
        ip = param[CENSYS_JSON_IP]
        if not self._is_ip(ip):
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid value in the 'ip' action parameter")
        ret_val, response = self._make_rest_call(endpoint.format(ip), action_result, method=req_method)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not response.get('result').get('services'):
            return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)

        summary_data['port'] = response.get('result').get('services')[0].get('port')
        summary_data['service_name'] = response.get('result').get('services')[0].get('service_name')

        action_result.add_data(response)

        self._update_summary(action_result, response)

        self.debug_print("Exiting _lookup_ip")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _query_ip(self, param):

        self.debug_print("Entering _query_ip")

        action_result = self.add_action_result(ActionResult(param))
        summary_data = action_result.update_summary({})
        hits = []
        query = param[CENSYS_JSON_QUERY]
        ret_val, limit = self._validate_integer(action_result, param.get('limit', 200), CENSYS_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        req_method, endpoint = CENSYS_API_METHOD_MAP.get("hosts_search")
        if limit < CENSYS_QUERY_IP_DATA_PER_PAGE:
            endpoint_url = endpoint.format(query, limit)
        else:
            endpoint_url = endpoint.format(query, CENSYS_QUERY_IP_DATA_PER_PAGE)

        ret_val, response = self._make_rest_call(endpoint_url, action_result, method=req_method)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        hits = response.get('result').get('hits')
        next = response.get('result').get('links').get('next')
        total_records = response.get('result').get('total')

        data_left = limit - CENSYS_QUERY_IP_DATA_PER_PAGE
        while next and data_left > 0:
            if data_left < CENSYS_QUERY_IP_DATA_PER_PAGE:
                endpoint_url = endpoint.format(query, data_left)
            time.sleep(1.5)
            ret_val, response_json = self._make_rest_call('{}&cursor={}'.format(endpoint_url, next), action_result, method='get')
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            data_left -= CENSYS_QUERY_IP_DATA_PER_PAGE

            for hit in response_json.get('result').get('hits'):
                hits.append(hit)
            next = response_json.get('result').get('links').get('next')

        for hit in hits:
            action_result.add_data(hit)

        summary_data['total_records_fetched'] = len(hits)
        summary_data['total_available_records'] = total_records
        self._update_summary(action_result, response)

        self.debug_print("Exiting _query_ip")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_certificate(self, param):

        self.debug_print("Entering _lookup_certificate")

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_view(param[CENSYS_JSON_SHA256], "certificates", action_result)

        if phantom.is_fail(ret_val):
            message = action_result.get_message()
            if 'do not know anything' in message:
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        # summary
        parsed = response.get('parsed', {})

        if parsed:

            summary = {}

            validity = parsed.get('validity')

            if validity:
                valid_from = validity.get('start')
                valid_to = validity.get('end')
                summary.update({'valid_from': valid_from, 'valid_to': valid_to})

            summary.update({'issuer_dn': parsed.get('issuer_dn'), 'subject_dn': parsed.get('subject_dn')})

            action_result.update_summary(summary)

        self.debug_print("Exiting _lookup_certificate")

        return ret_val

    def _update_summary(self, action_result, response):

        protocols = response.get('protocols')

        if protocols:
            if not isinstance(protocols, list):
                protocols = [protocols]

            protocols = ', '.join(protocols)
            action_result.update_summary({'protocols': protocols})

        return action_result

    def _lookup_domain(self, param):

        self.debug_print("Entering _lookup_domain")

        action_result = self.add_action_result(ActionResult(param))

        self.debug_print("Exiting _lookup_domain")

        return action_result.set_status(phantom.APP_ERROR, 'This action is not yet supported by Censys in API v2')

    def _query_domain(self, param):
        """ Use handle_search to query the correct dataset with the query string
        """

        self.debug_print(f"Entering _query_domain")

        action_result = self.add_action_result(ActionResult(param))

        self.debug_print("Exiting _query_domain")

        return action_result.set_status(phantom.APP_ERROR, 'This action is not yet supported by Censys in API v2')

    def _query_certificate(self, param):
        """ Use handle_search to query the correct dataset with the query string
        """

        self.debug_print(f"Entering _query_certificate")

        action_result = self.add_action_result(ActionResult(param))
        summary_data = action_result.update_summary({})

        ret_val, limit = self._validate_integer(action_result, param.get('limit', 200), CENSYS_LIMIT_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        ret_val, response = self._handle_search(param[CENSYS_JSON_QUERY], CENSYS_QUERY_CERTIFICATE_DATASET, action_result, limit)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            total_results = min(response.get('metadata').get('count'), CENSYS_QUERY_CERTIFICATE_MAX_LIMIT)
            summary_data['total_records_fetched'] = min(limit, total_results)
            summary_data['total_available_records'] = response.get('metadata').get('count')
            self._update_summary(action_result, response)
            self.debug_print(f"Total results fetched: {min(limit, total_results)}")
            self.debug_print("Exiting _query_certificate")
            return action_result.set_status(phantom.APP_SUCCESS)
        except Exception as e:
            summary_data['total_records_fetched'] = 'not found'
            summary_data['total_available_records'] = response.get('metadata').get('count')
            self._update_summary(action_result, response)
            self.debug_print(f"An exception occurred: {e}")
            self.debug_print("Exiting _query_certificate")
            return action_result.set_status(phantom.APP_ERROR, 'unable to parse result count')

    def handle_action(self, param):

        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            ret_val = self._test_connectivity(param)
        elif action == self.ACTION_LOOKUP_IP:
            ret_val = self._lookup_ip(param)
        elif action == self.ACTION_LOOKUP_CERTIFICATE:
            ret_val = self._lookup_certificate(param)
        elif action == self.ACTION_LOOKUP_DOMAIN:
            ret_val = self._lookup_domain(param)
        elif action == self.ACTION_QUERY_IP:
            ret_val = self._query_ip(param)
        elif action == self.ACTION_QUERY_DOMAIN:
            ret_val = self._query_domain(param)
        elif action == self.ACTION_QUERY_CERTIFICATE:
            ret_val = self._query_certificate(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        """
        # Access values in asset config by the name
        # Required values can be accessed directly
        required_config_name = config['required_config_name']
        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CensysConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
