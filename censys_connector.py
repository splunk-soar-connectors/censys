# --
# File: censys/censys_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from censys_consts import *

import requests
import simplejson as json


class CensysConnector(BaseConnector):

    ACTION_QUERY_IP = "lookup_ip"
    ACTION_QUERY_CERTIFICATE = "lookup_certificate"
    ACTION_QUERY_DOMAIN = "lookup_domain"

    def __init__(self):
        self._headers = {}
        super(CensysConnector, self).__init__()
        return

    def _parse_http_error(self, action_result, r):

        if ('json' not in r.headers.get('Content-Type', '')):
            return ""

        try:
            resp_json = r.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to Parse response as JSON"), None)

        message = "Server returned error with Status: {0}, Type: {1}, Detail: {2}".format(
                resp_json.get('status', 'NA'), resp_json.get('error_type', 'NA'), resp_json.get('error', 'NA'))

        return action_result.set_status(phantom.APP_ERROR, message)

    def _make_rest_call(self, endpoint, action_result, data=None, method="post"):

        # Create the header
        resp_json = None

        config = self.get_config()
        request_func = getattr(requests, method)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        try:
            response = request_func(CENSYS_API_URL + endpoint, json=data,
                    auth=(config[CENSYS_JSON_API_ID], config[CENSYS_JSON_SECRET]), headers=headers)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to connect to the server", e), resp_json)

        if (response.status_code not in (200, 429)):
            # error, possibly
            return (self._parse_http_error(action_result, response), {})

        try:
            resp_json = response.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON"), None)

        if (resp_json.get('status', '') == 'error'):
            return (self._parse_http_error(action_result, response), {})

        return (phantom.APP_SUCCESS, resp_json)

    def _test_connectivity(self, param):
        """ Test connectivity by retrieving a valid token
        """

        action_result = ActionResult()
        self.save_progress("Testing connectivity")

        ret_val, response = self._handle_view('censys.io', "websites", action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            self.save_progress("Connectivity test failed")
            return self.set_status(phantom.APP_ERROR,)

        self.save_progress("Connectivity test passed")
        return self.set_status(phantom.APP_SUCCESS, "Connectivity test passed")

    def _check_datapath(self, datadict):
            for i in datadict.keys():
                if "." in i:
                    datadict[i.replace(".", "_")] = datadict[i]
                    del(datadict[i])
            return datadict

    def _handle_search(self, query_string, search_action, action_result):

            req_method, api = CENSYS_API_METHOD_MAP.get("search")

            data = {"query": query_string}

            ret_val, response = self._make_rest_call(api + search_action, action_result, data=data, method=req_method)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for res in response.get("results", []):
                action_result.add_data(self._check_datapath(res))

            action_result.set_status(phantom.APP_SUCCESS)

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

    def _query_ip(self, param):

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_view(param[CENSYS_JSON_IP], "ipv4", action_result)

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if ("don't know anything" in message):
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        self._update_summary(action_result, response)

        return ret_val

    def _query_certificate(self, param):

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_view(param[CENSYS_JSON_SHA256], "certificates", action_result)

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if ('do not know anything' in message):
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        # summary
        parsed = response.get('parsed', {})

        if (parsed):

            summary = {}

            validity = parsed.get('validity')

            if (validity):
                valid_from = validity.get('start')
                valid_to = validity.get('end')
                summary.update({'valid_from': valid_from, 'valid_to': valid_to})

            summary.update({'issuer_dn': parsed.get('issuer_dn'), 'subject_dn': parsed.get('subject_dn')})

            action_result.update_summary(summary)

        return ret_val

    def _update_summary(self, action_result, response):

        protocols = response.get('protocols')

        if (protocols):
            if (type(protocols) != list):
                protocols = [protocols]

            protocols = ', '.join(protocols)
            action_result.update_summary({'protocols': protocols})

        return action_result

    def _query_domain(self, param):

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_view(param[CENSYS_JSON_DOMAIN], "websites", action_result)

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if ('do not know anything' in message):
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        self._update_summary(action_result, response)

        return ret_val

    def handle_action(self, param):

        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action == self.ACTION_QUERY_IP):
            ret_val = self._query_ip(param)
        elif (action == self.ACTION_QUERY_CERTIFICATE):
            ret_val = self._query_certificate(param)
        elif (action == self.ACTION_QUERY_DOMAIN):
            ret_val = self._query_domain(param)

        return ret_val

if __name__ == '__main__':
    # Imports
    import sys

    import pudb

    # Breakpoint at runtime
    pudb.set_trace()
    # The first param is the input json file
    with open(sys.argv[1]) as f:

        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        # Create the connector class object
        connector = CensysConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print ret_val

    exit(0)
