# File: censys_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

CENSYS_API_URL = "https://search.censys.io"
CENSYS_API_METHOD_MAP = {
                    "hosts": ("get", "/api/v2/hosts/{0}"),
                    "hosts_search": ("get", "/api/v2/hosts/search?q={}&per_page={}"),
                    "query": ("post", "/api/v1/query"),
                    "report": ("post", "/api/v1/report/{0}"),
                    "search": ("post", "/api/v1/search/"),
                    "view": ("get", "/api/v1/view/{0}/{1}"),
                    "data": ("get", "/api/v1/data/domain/20151013T2353")}

CENSYS_JSON_API_ID = "api_id"
CENSYS_JSON_SECRET = "secret"
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

# constants relating to "get_error_msg_from_exception"
CENSYS_ERR_CODE_MSG = "Error code unavailable"
CENSYS_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
CENSYS_PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# constants for integer validation
CENSYS_INT_ERR_MSG = "Please provide a valid integer value in the {key}"
CENSYS_LIMIT_KEY = "'limit' action parameter"
