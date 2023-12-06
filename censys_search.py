# File: censys_search.py
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
import phantom.app as phantom

from censys_consts import CENSYS_API_METHOD_MAP, CENSYS_JSON_QUERY, CENSYS_LIMIT_KEY
from censys_validation import validate_integer


class CensysSearch:
    def __init__(self, make_rest_call) -> None:
        self._make_rest_call = make_rest_call
        self._req_method, self._endpoint = CENSYS_API_METHOD_MAP["search"]

    def query_dataset(self, action_result, summary_data, dataset, param, per_page):
        """Search Censys using the given query string in the Censys search language. censys_io_dataset specifies
        which type of data you are searching. At the time of writing there are 3 datasets: certificates,
        hosts, and websites (domains).
        """
        query = param[CENSYS_JSON_QUERY]
        ret_val, limit = validate_integer(
            action_result, param.get("limit", 200), CENSYS_LIMIT_KEY
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, response = self._search_call(
            action_result, dataset, query, per_page, limit
        )
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        hits = self._get_hits(response)
        next = self._get_next(response)
        total = self._get_total(response)

        data_left = limit - len(hits)
        while next != "" and data_left > 0:
            ret_val, next_response = self._search_call(
                action_result, dataset, query, min(per_page, data_left), limit, next
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status(), next_response
            next_hits = self._get_hits(next_response)
            hits.extend(next_hits)
            next = self._get_next(next_response)
            data_left -= len(next_hits)

        for hit in hits:
            action_result.add_data(hit)

        summary_data["total_records_fetched"] = len(hits)
        summary_data["total_available_records"] = total
        return action_result.set_status(phantom.APP_SUCCESS), response

    def _search_call(self, action_result, dataset, q, per_page, limit, cursor=""):
        cursor_q = "" if cursor == "" else f"&cursor={cursor}"
        endpoint_url = self._endpoint.format(
            dataset=dataset, q=q, per_page=min(limit, per_page)
        )
        return self._make_rest_call(
            f"{endpoint_url}{cursor_q}", action_result, method=self._req_method
        )

    def _check_datapath(self, datadict):
        for i in datadict:
            if "." in i:
                datadict[i.replace(".", "_")] = datadict[i]
                del datadict[i]
        return datadict

    @staticmethod
    def _get_hits(response):
        return response.get("result").get("hits")

    @staticmethod
    def _get_next(response):
        return response.get("result").get("links").get("next")

    @staticmethod
    def _get_total(response):
        return response.get("result").get("total")
