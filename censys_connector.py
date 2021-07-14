# File: censys_connector.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from censys_consts import *

import requests
import json


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

        if ('json' not in r.headers.get('Content-Type', '')):
            return ""

        try:
            resp_json = r.json()
        except:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to parse response as JSON"), None)

        message = "Server returned error with status: {0}, Type: {1}, Detail: {2}".format(
                resp_json.get('status', 'NA'), resp_json.get('error_type', 'NA'), resp_json.get('error', 'NA'))

        return action_result.set_status(phantom.APP_ERROR, message)

    def _make_rest_call(self, endpoint, action_result, data=None, method="post"):

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
        for i in list(datadict.keys()):
            if "." in i:
                datadict[i.replace(".", "_")] = datadict[i]
                del(datadict[i])
        return datadict

    def _handle_search(self, query_string, censys_io_dataset, action_result):
        """ Search Censys using the given query string in the Censys search language. censys_io_dataset specifies
            which type of data you are searching. At the time of writing there are 3 datasets: certificates,
            ipv4hosts, and websites (domains).
        """

        req_method, api = CENSYS_API_METHOD_MAP.get("search")
        data = {"query": query_string}

        ret_val, response = self._make_rest_call(api + censys_io_dataset, action_result, data=data, method=req_method)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), action_result.get_message())

        num_pages = response.get('metadata', {}).get('pages', None)
        if num_pages is None:
            return (action_result.set_status(phantom.APP_ERROR), None)

        for res in response.get("results", []):
            action_result.add_data(self._check_datapath(res))

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        config = self.get_config()
        auth = (config[CENSYS_JSON_API_ID], config[CENSYS_JSON_SECRET])
        for page in range(2, num_pages + 1):
            self.debug_print("requesting page {} out of {}".format(page, num_pages))
            data['page'] = page
            page_response = requests.post(CENSYS_API_URL + api + censys_io_dataset, data=json.dumps(data), headers=headers, auth=auth)
            if page_response.status_code != 200:
                self.debug_print("received {} response with body {}".format(page_response.status_code, page_response.text))
                return action_result.set_status(phantom.APP_SUCCESS), response

            response_json = page_response.json()
            for result in response_json.get("results", []):
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

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_view(param[CENSYS_JSON_IP], "ipv4", action_result)

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if ("don't know anything" in message):
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        self._update_summary(action_result, response)

        return ret_val

    def _lookup_certificate(self, param):

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

    def _lookup_domain(self, param):

        action_result = self.add_action_result(ActionResult(param))
        ret_val, response = self._handle_view(param[CENSYS_JSON_DOMAIN], "websites", action_result)

        if (phantom.is_fail(ret_val)):
            message = action_result.get_message()
            if ('do not know anything' in message):
                return action_result.set_status(phantom.APP_SUCCESS, CENSYS_NO_INFO)
            return ret_val

        self._update_summary(action_result, response)

        return ret_val

    def _query_dataset(self, param, dataset):
        """ Use handle_search to query the correct dataset with the query string
        """

        action_result = self.add_action_result(ActionResult(param))

        ret_val, response = self._handle_search(param[CENSYS_JSON_QUERY], dataset, action_result)

        if (phantom.is_fail(ret_val)):
            return ret_val

        try:
            action_result.update_summary({'result_count': response['metadata']['count']})
        except:
            action_result.update_summary({'result_count': 'Not found'})
            return action_result.set_status(phantom.APP_ERROR, 'unable to parse result count')

        return ret_val

    def handle_action(self, param):

        action = self.get_action_identifier()

        ret_val = phantom.APP_SUCCESS

        if (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action == self.ACTION_LOOKUP_IP):
            ret_val = self._lookup_ip(param)
        elif (action == self.ACTION_LOOKUP_CERTIFICATE):
            ret_val = self._lookup_certificate(param)
        elif (action == self.ACTION_LOOKUP_DOMAIN):
            ret_val = self._lookup_domain(param)
        elif (action == self.ACTION_QUERY_IP):
            ret_val = self._query_dataset(param, QUERY_IP_DATASET)
        elif (action == self.ACTION_QUERY_DOMAIN):
            ret_val = self._query_dataset(param, QUERY_DOMAIN_DATASET)
        elif (action == self.ACTION_QUERY_CERTIFICATE):
            ret_val = self._query_dataset(param, QUERY_CERTIFICATE_DATASET)

        return ret_val


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
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

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
