# File: censys_consts.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
CENSYS_API_URL = "https://search.censys.io"
CENSYS_API_METHOD_MAP = {
    "info": ("get", "/api/v2/{dataset}/{value}"),
    "search": ("get", "/api/v2/{dataset}/search?q={q}&per_page={per_page}"),
}

CENSYS_JSON_API_ID = "api_id"
CENSYS_JSON_SECRET = "secret"  # pragma: allowlist secret
CENSYS_JSON_SHA256 = "sha256"
CENSYS_JSON_IP = "ip"
CENSYS_JSON_DOMAIN = "domain"
CENSYS_NO_INFO = "No information found about the queried item"
CENSYS_JSON_DATASET = "dataset"
CENSYS_JSON_QUERY = "query"
CENSYS_QUERY_IP_DATASET = "ipv4"
CENSYS_QUERY_IP_DATA_PER_PAGE = 100
CENSYS_QUERY_CERTIFICATE_DATA_PER_PAGE = 100
CENSYS_QUERY_CERTIFICATE_MAX_LIMIT = 25000
CENSYS_QUERY_DOMAIN_DATASET = "websites"
CENSYS_QUERY_CERTIFICATE_DATASET = "certificates"
CENSYS_QUERY_HOSTS_DATASET = "hosts"

# constants relating to "get_error_msg_from_exception"
CENSYS_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
CENSYS_ERR_JSON_DECODE = "Unable to parse response as JSON: {} Raw text: {}"

# constants for integer validation
CENSYS_INT_ERR_MSG = "Please provide a valid integer value in the {key}"
CENSYS_LIMIT_KEY = "'limit' action parameter"

CENSYS_DEFAULT_TIMEOUT = 120

# Action names
CENSYS_TEST_CONNECTIVITY_ACTION = "test_connectivity"
CENSYS_LOOKUP_IP_ACTION = "lookup_ip"
CENSYS_LOOKUP_DOMAIN_ACTION = "lookup_domain"
CENSYS_LOOKUP_CERTIFICATE_ACTION = "lookup_certificate"
CENSYS_QUERY_IP_ACTION = "query_ip"
CENSYS_QUERY_DOMAIN_ACTION = "query_domain"
CENSYS_QUERY_CERTIFICATE_ACTION = "query_certificate"
