# --
# File: censys/censys_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

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
