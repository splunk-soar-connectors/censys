# File: censys_consts.py
# Copyright (c) 2016-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

CENSYS_API_URL = "https://www.censys.io"
CENSYS_API_METHOD_MAP = {
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
QUERY_IP_DATASET = "ipv4"
QUERY_DOMAIN_DATASET = "websites"
QUERY_CERTIFICATE_DATASET = "certificates"
