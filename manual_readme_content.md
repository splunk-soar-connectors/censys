[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The **app_id** and **secret** asset configuration values can be found on the Censys website under
the **My Account** -> **API** section.

When using the *query ip* , *query domain* and *query certificate* actions, the full Censys search
syntax may be used within the query. For examples and syntax help, see [the certificate search
documentation](https://search.censys.io/certificates/help?q=&) and similar pages.

### Note:

1.  'Lookup Domain' and 'Query Domain' actions will not work in this version of the app as Censys
    has not added support for these actions in API V2. For more details refer to pdf attached to
    this [Censys
    page](https://support.censys.io/hc/en-us/articles/4404436837652-Search-1-0-and-IPv4-Banners-Deprecated-Resources-and-Available-Alternatives)
    .
2.  'Query IP' and 'Query Certificate' action makes 1 API call for every 100 results. For example,
    to fetch the 5000 results, 50 API calls will be made. If a query is fired for large number of
    records and the limit specified in the limit parameter is too large, user's account may exceed
    the query quota provided by Censys.
3.  As per the limit provided by Censys, 'Query Certificate' action can fetch only 25,000 data at
    max.
