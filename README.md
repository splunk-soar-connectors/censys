[comment]: # "Auto-generated SOAR connector documentation"
# Censys

Publisher: Splunk  
Connector Version: 2\.1\.11  
Product Vendor: Censys  
Product Name: Censys  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app implements investigative actions to get information from the Censys search engine

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2021 Splunk Inc."
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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Censys asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_id** |  required  | password | API ID
**secret** |  required  | password | Secret

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate connectivity to Censys  
[lookup certificate](#action-lookup-certificate) - Lookup certificate info  
[lookup ip](#action-lookup-ip) - Lookup ip info  
[lookup domain](#action-lookup-domain) - Lookup Domain info  
[query domain](#action-query-domain) - Query the domain dataset  
[query certificate](#action-query-certificate) - Query the certificate dataset  
[query ip](#action-query-ip) - Query the IP dataset  

## action: 'test connectivity'
Validate connectivity to Censys

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup certificate'
Lookup certificate info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sha256** |  required  | SHA256 fingerprint of certificate | string |  `hash`  `sha256` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.sha256 | string |  `hash`  `sha256` 
action\_result\.data\.\*\.audit\.nss\.is\_in | boolean | 
action\_result\.data\.\*\.audit\.nss\.was\_in | boolean | 
action\_result\.data\.\*\.ct\.comodo\_dodo\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.comodo\_dodo\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.comodo\_dodo\.index | numeric | 
action\_result\.data\.\*\.ct\.digicert\_ct1\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.digicert\_ct1\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.digicert\_ct1\.index | numeric | 
action\_result\.data\.\*\.ct\.google\_aviator\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_aviator\.censys\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_aviator\.censys\_to\_ct\_status | string | 
action\_result\.data\.\*\.ct\.google\_aviator\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.google\_aviator\.index | numeric | 
action\_result\.data\.\*\.ct\.google\_aviator\.sct | string | 
action\_result\.data\.\*\.ct\.google\_pilot\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_pilot\.censys\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_pilot\.censys\_to\_ct\_status | string | 
action\_result\.data\.\*\.ct\.google\_pilot\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.google\_pilot\.index | numeric | 
action\_result\.data\.\*\.ct\.google\_pilot\.sct | string | 
action\_result\.data\.\*\.ct\.google\_rocketeer\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_rocketeer\.censys\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_rocketeer\.censys\_to\_ct\_status | string | 
action\_result\.data\.\*\.ct\.google\_rocketeer\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.google\_rocketeer\.index | numeric | 
action\_result\.data\.\*\.ct\.google\_rocketeer\.sct | string | 
action\_result\.data\.\*\.ct\.google\_submariner\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.google\_submariner\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.google\_submariner\.index | numeric | 
action\_result\.data\.\*\.ct\.symantec\_ws\_ct\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.symantec\_ws\_ct\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.symantec\_ws\_ct\.index | numeric | 
action\_result\.data\.\*\.ct\.symantec\_ws\_deneb\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.symantec\_ws\_deneb\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.symantec\_ws\_deneb\.index | numeric | 
action\_result\.data\.\*\.ct\.symantec\_ws\_vega\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.symantec\_ws\_vega\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.symantec\_ws\_vega\.index | numeric | 
action\_result\.data\.\*\.ct\.venafi\_api\_ctlog\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.venafi\_api\_ctlog\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.venafi\_api\_ctlog\.index | numeric | 
action\_result\.data\.\*\.ct\.wosign\_ctlog\.added\_to\_ct\_at | string | 
action\_result\.data\.\*\.ct\.wosign\_ctlog\.ct\_to\_censys\_at | string | 
action\_result\.data\.\*\.ct\.wosign\_ctlog\.index | numeric | 
action\_result\.data\.\*\.current\_in\_nss | boolean | 
action\_result\.data\.\*\.current\_valid\_nss | boolean | 
action\_result\.data\.\*\.fingerprint\_sha256 | string | 
action\_result\.data\.\*\.in\_nss | boolean | 
action\_result\.data\.\*\.metadata\.added\_at | string | 
action\_result\.data\.\*\.metadata\.parse\_status | string | 
action\_result\.data\.\*\.metadata\.parse\_version | numeric | 
action\_result\.data\.\*\.metadata\.post\_processed | boolean | 
action\_result\.data\.\*\.metadata\.post\_processed\_at | string | 
action\_result\.data\.\*\.metadata\.seen\_in\_scan | boolean | 
action\_result\.data\.\*\.metadata\.source | string | 
action\_result\.data\.\*\.metadata\.updated\_at | string | 
action\_result\.data\.\*\.parent\_spki\_subject\_fingerprint | string | 
action\_result\.data\.\*\.parents | string | 
action\_result\.data\.\*\.parsed\.extensions\.authority\_info\_access\.ocsp\_urls | string | 
action\_result\.data\.\*\.parsed\.extensions\.authority\_key\_id | string | 
action\_result\.data\.\*\.parsed\.extensions\.basic\_constraints\.is\_ca | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.basic\_constraints\.max\_path\_len | numeric | 
action\_result\.data\.\*\.parsed\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.parsed\.extensions\.certificate\_policies\.\*\.id | string | 
action\_result\.data\.\*\.parsed\.extensions\.certificate\_policies\.\*\.user\_notice\.\*\.explicit\_text | string | 
action\_result\.data\.\*\.parsed\.extensions\.crl\_distribution\_points | string | 
action\_result\.data\.\*\.parsed\.extensions\.ct\_poison | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.extended\_key\_usage\.client\_auth | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.extended\_key\_usage\.server\_auth | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.key\_usage\.certificate\_sign | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.key\_usage\.crl\_sign | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.key\_usage\.digital\_signature | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.key\_usage\.key\_encipherment | boolean | 
action\_result\.data\.\*\.parsed\.extensions\.key\_usage\.value | numeric | 
action\_result\.data\.\*\.parsed\.extensions\.subject\_alt\_name\.directory\_names\.\*\.common\_name | string | 
action\_result\.data\.\*\.parsed\.extensions\.subject\_key\_id | string | 
action\_result\.data\.\*\.parsed\.fingerprint\_md5 | string | 
action\_result\.data\.\*\.parsed\.fingerprint\_sha1 | string | 
action\_result\.data\.\*\.parsed\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.parsed\.issuer\.common\_name | string | 
action\_result\.data\.\*\.parsed\.issuer\.country | string | 
action\_result\.data\.\*\.parsed\.issuer\.organization | string | 
action\_result\.data\.\*\.parsed\.issuer\.organizational\_unit | string | 
action\_result\.data\.\*\.parsed\.issuer\_dn | string | 
action\_result\.data\.\*\.parsed\.redacted | boolean | 
action\_result\.data\.\*\.parsed\.serial\_number | string | 
action\_result\.data\.\*\.parsed\.signature\.self\_signed | boolean | 
action\_result\.data\.\*\.parsed\.signature\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.parsed\.signature\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.parsed\.signature\.valid | boolean | 
action\_result\.data\.\*\.parsed\.signature\.value | string | 
action\_result\.data\.\*\.parsed\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.parsed\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.parsed\.spki\_subject\_fingerprint | string | 
action\_result\.data\.\*\.parsed\.subject\.common\_name | string | 
action\_result\.data\.\*\.parsed\.subject\.country | string | 
action\_result\.data\.\*\.parsed\.subject\.organization | string | 
action\_result\.data\.\*\.parsed\.subject\.organizational\_unit | string | 
action\_result\.data\.\*\.parsed\.subject\_dn | string | 
action\_result\.data\.\*\.parsed\.subject\_key\_info\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.parsed\.subject\_key\_info\.key\_algorithm\.name | string | 
action\_result\.data\.\*\.parsed\.subject\_key\_info\.key\_algorithm\.oid | string | 
action\_result\.data\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.exponent | numeric | 
action\_result\.data\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.length | numeric | 
action\_result\.data\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.modulus | string | 
action\_result\.data\.\*\.parsed\.tbs\_fingerprint | string | 
action\_result\.data\.\*\.parsed\.tbs\_noct\_fingerprint | string | 
action\_result\.data\.\*\.parsed\.validation\_level | string | 
action\_result\.data\.\*\.parsed\.validity\.end | string | 
action\_result\.data\.\*\.parsed\.validity\.length | numeric | 
action\_result\.data\.\*\.parsed\.validity\.start | string | 
action\_result\.data\.\*\.parsed\.version | numeric | 
action\_result\.data\.\*\.post\_processed | boolean | 
action\_result\.data\.\*\.precert | boolean | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.seen\_in\_scan | boolean | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.updated\_at | string | 
action\_result\.data\.\*\.valid\_nss | boolean | 
action\_result\.data\.\*\.validation\.apple\.blacklisted | boolean | 
action\_result\.data\.\*\.validation\.apple\.had\_trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.apple\.in\_revocation\_set | boolean | 
action\_result\.data\.\*\.validation\.apple\.trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.apple\.type | string | 
action\_result\.data\.\*\.validation\.apple\.valid | boolean | 
action\_result\.data\.\*\.validation\.apple\.was\_valid | boolean | 
action\_result\.data\.\*\.validation\.apple\.whitelisted | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.blacklisted | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.had\_trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.in\_revocation\_set | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.type | string | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.valid | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.was\_valid | boolean | 
action\_result\.data\.\*\.validation\.google\_ct\_primary\.whitelisted | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.blacklisted | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.had\_trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.in\_revocation\_set | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.type | string | 
action\_result\.data\.\*\.validation\.microsoft\.valid | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.was\_valid | boolean | 
action\_result\.data\.\*\.validation\.microsoft\.whitelisted | boolean | 
action\_result\.data\.\*\.validation\.nss\.blacklisted | boolean | 
action\_result\.data\.\*\.validation\.nss\.had\_trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.nss\.in\_revocation\_set | boolean | 
action\_result\.data\.\*\.validation\.nss\.trusted\_path | boolean | 
action\_result\.data\.\*\.validation\.nss\.type | string | 
action\_result\.data\.\*\.validation\.nss\.valid | boolean | 
action\_result\.data\.\*\.validation\.nss\.was\_valid | boolean | 
action\_result\.data\.\*\.validation\.nss\.whitelisted | boolean | 
action\_result\.data\.\*\.validation\.revoked | boolean | 
action\_result\.data\.\*\.validation\_timestamp | string | 
action\_result\.data\.\*\.was\_in\_nss | boolean | 
action\_result\.data\.\*\.was\_valid\_nss | boolean | 
action\_result\.data\.\*\.zlint\.errors\_present | boolean | 
action\_result\.data\.\*\.zlint\.fatals\_present | boolean | 
action\_result\.data\.\*\.zlint\.lints\.n\_contains\_redacted\_dnsname | boolean | 
action\_result\.data\.\*\.zlint\.lints\.n\_subject\_common\_name\_included | boolean | 
action\_result\.data\.\*\.zlint\.lints\.w\_ext\_subject\_key\_identifier\_missing\_sub\_cert | boolean | 
action\_result\.data\.\*\.zlint\.notices\_present | boolean | 
action\_result\.data\.\*\.zlint\.version | numeric | 
action\_result\.data\.\*\.zlint\.warnings\_present | boolean | 
action\_result\.summary\.issuer\_dn | string | 
action\_result\.summary\.subject\_dn | string | 
action\_result\.summary\.valid\_from | string | 
action\_result\.summary\.valid\_to | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup ip'
Lookup ip info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to get info of | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.443\.https\.dhe\.support | boolean | 
action\_result\.data\.\*\.443\.https\.dhe\_export\.support | boolean | 
action\_result\.data\.\*\.443\.https\.rsa\_export\.support | boolean | 
action\_result\.data\.\*\.autonomous\_system\.asn | numeric | 
action\_result\.data\.\*\.autonomous\_system\.country\_code | string | 
action\_result\.data\.\*\.autonomous\_system\.description | string | 
action\_result\.data\.\*\.autonomous\_system\.name | string | 
action\_result\.data\.\*\.autonomous\_system\.rir | string | 
action\_result\.data\.\*\.autonomous\_system\.routed\_prefix | string | 
action\_result\.data\.\*\.code | numeric | 
action\_result\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.location\.continent | string | 
action\_result\.data\.\*\.location\.country | string | 
action\_result\.data\.\*\.location\.country\_code | string | 
action\_result\.data\.\*\.location\.latitude | numeric | 
action\_result\.data\.\*\.location\.longitude | numeric | 
action\_result\.data\.\*\.location\.registered\_country | string | 
action\_result\.data\.\*\.location\.registered\_country\_code | string | 
action\_result\.data\.\*\.location\.timezone | string | 
action\_result\.data\.\*\.result\.autonomous\_system\.asn | numeric | 
action\_result\.data\.\*\.result\.autonomous\_system\.bgp\_prefix | string | 
action\_result\.data\.\*\.result\.autonomous\_system\.country\_code | string | 
action\_result\.data\.\*\.result\.autonomous\_system\.description | string | 
action\_result\.data\.\*\.result\.autonomous\_system\.name | string | 
action\_result\.data\.\*\.result\.autonomous\_system\_updated\_at | string | 
action\_result\.data\.\*\.result\.dns\.records\.ec2\-3\-8\-0\-0\.eu\-west\-2\.compute\.amazonaws\.com\.record\_type | string | 
action\_result\.data\.\*\.result\.dns\.records\.ec2\-3\-8\-0\-0\.eu\-west\-2\.compute\.amazonaws\.com\.resolved\_at | string | 
action\_result\.data\.\*\.result\.dns\.records\.origin\-www\.amazon\.com\.record\_type | string | 
action\_result\.data\.\*\.result\.dns\.records\.origin\-www\.amazon\.com\.resolved\_at | string | 
action\_result\.data\.\*\.result\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.result\.last\_updated\_at | string | 
action\_result\.data\.\*\.result\.location\.city | string | 
action\_result\.data\.\*\.result\.location\.continent | string | 
action\_result\.data\.\*\.result\.location\.coordinates\.latitude | numeric | 
action\_result\.data\.\*\.result\.location\.coordinates\.longitude | numeric | 
action\_result\.data\.\*\.result\.location\.country | string | 
action\_result\.data\.\*\.result\.location\.country\_code | string | 
action\_result\.data\.\*\.result\.location\.postal\_code | string | 
action\_result\.data\.\*\.result\.location\.province | string | 
action\_result\.data\.\*\.result\.location\.registered\_country | string | 
action\_result\.data\.\*\.result\.location\.registered\_country\_code | string | 
action\_result\.data\.\*\.result\.location\.timezone | string | 
action\_result\.data\.\*\.result\.location\_updated\_at | string | 
action\_result\.data\.\*\.result\.operating\_system\.other\.family | string | 
action\_result\.data\.\*\.result\.operating\_system\.part | string | 
action\_result\.data\.\*\.result\.operating\_system\.product | string | 
action\_result\.data\.\*\.result\.operating\_system\.uniform\_resource\_identifier | string | 
action\_result\.data\.\*\.result\.operating\_system\.vendor | string | 
action\_result\.data\.\*\.result\.services\.\*\.\_decoded | string | 
action\_result\.data\.\*\.result\.services\.\*\.\_encoding\.banner | string | 
action\_result\.data\.\*\.result\.services\.\*\.\_encoding\.banner\_hex | string | 
action\_result\.data\.\*\.result\.services\.\*\.\_encoding\.certificate | string | 
action\_result\.data\.\*\.result\.services\.\*\.banner | string | 
action\_result\.data\.\*\.result\.services\.\*\.banner\_hex | string | 
action\_result\.data\.\*\.result\.services\.\*\.certificate | string | 
action\_result\.data\.\*\.result\.services\.\*\.extended\_service\_name | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.request\.headers\.\_encoding\.Accept | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.request\.headers\.\_encoding\.User\_Agent | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.request\.method | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.request\.uri | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.\_encoding\.body | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.\_encoding\.body\_hash | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.\_encoding\.html\_tags | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.\_encoding\.html\_title | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.body | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.body\_hash | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.body\_size | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Accept\_Ranges | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Cache\_Control | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Connection | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Content\_Length | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Content\_Type | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Date | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Etag | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Expires | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Last\_Modified | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Location | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Referrer\_Policy | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Server | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Set\_Cookie | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.Vary | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Content\_Type\_Options | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Frame\_Options | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Hudson | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Jenkins | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Jenkins\_Session | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Matomo\_Request\_Id | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.headers\.\_encoding\.X\_Powered\_By | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.html\_title | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.protocol | string | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.status\_code | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.http\.response\.status\_reason | string | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.\_encoding\.auth\_plugin\_data | string | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.auth\_plugin\_data | string | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.auth\_plugin\_name | string | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_CAN\_HANDLE\_EXPIRED\_PASSWORDS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_COMPRESS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_CONNECT\_ATTRS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_CONNECT\_WITH\_DB | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_DEPRECATED\_EOF | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_FOUND\_ROWS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_IGNORE\_SIGPIPE | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_IGNORE\_SPACE | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_INTERACTIVE | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_LOCAL\_FILES | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_LONG\_FLAG | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_LONG\_PASSWORD | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_MULTI\_RESULTS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_MULTI\_STATEMENTS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_NO\_SCHEMA | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_ODBC | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_PLUGIN\_AUTH | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_PLUGIN\_AUTH\_LEN\_ENC\_CLIENT\_DATA | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_PROTOCOL\_41 | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_PS\_MULTI\_RESULTS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_RESERVED | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_SECURE\_CONNECTION | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_SESSION\_TRACK | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_SSL | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.capability\_flags\.CLIENT\_TRANSACTIONS | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.character\_set | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.connection\_id | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.error\_code | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.protocol\_version | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.server\_version | string | 
action\_result\.data\.\*\.result\.services\.\*\.mysql\.status\_flags\.SERVER\_STATUS\_AUTOCOMMIT | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.observed\_at | string | 
action\_result\.data\.\*\.result\.services\.\*\.perspective\_id | string | 
action\_result\.data\.\*\.result\.services\.\*\.port | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.service\_name | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.other\.family | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.other\.info | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.part | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.product | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.source | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.uniform\_resource\_identifier | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.vendor | string | 
action\_result\.data\.\*\.result\.services\.\*\.software\.\*\.version | string | 
action\_result\.data\.\*\.result\.services\.\*\.source\_ip | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.client\_to\_server\_alg\_group\.cipher | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.client\_to\_server\_alg\_group\.compression | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.client\_to\_server\_alg\_group\.mac | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.host\_key\_algorithm | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.kex\_algorithm | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.server\_to\_client\_alg\_group\.cipher | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.server\_to\_client\_alg\_group\.compression | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.algorithm\_selection\.server\_to\_client\_alg\_group\.mac | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.endpoint\_id\.\_encoding\.raw | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.endpoint\_id\.protocol\_version | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.endpoint\_id\.raw | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.endpoint\_id\.software\_version | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.kex\_init\_message\.first\_kex\_follows | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.b | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.gx | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.gy | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.n | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.p | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.x | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.\_encoding\.y | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.b | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.curve | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.gx | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.gy | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.length | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.n | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.p | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.x | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.ecdsa\_public\_key\.y | string | 
action\_result\.data\.\*\.result\.services\.\*\.ssh\.server\_host\_key\.fingerprint\_sha256 | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.\_encoding\.chain\_fps\_sha\_256 | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.\_encoding\.leaf\_fp\_sha\_256 | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.chain\.\*\.fingerprint | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.chain\.\*\.issuer\_dn | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.chain\.\*\.subject\_dn | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.fingerprint | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.issuer\_dn | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.pubkey\_algorithm | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.pubkey\_bit\_size | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.fingerprint | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.key\_algorithm | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.rsa\.\_encoding\.exponent | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.rsa\.\_encoding\.modulus | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.rsa\.exponent | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.rsa\.length | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.public\_key\.rsa\.modulus | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.signature\.self\_signed | boolean | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.signature\.signature\_algorithm | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.subject\_dn | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_data\.tbs\_fingerprint | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.certificates\.leaf\_fp\_sha\_256 | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.cipher\_selected | string | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.server\_key\_exchange\.ec\_params\.named\_curve | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.session\_ticket\.length | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.session\_ticket\.lifetime\_hint | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.tls\.version\_selected | string | 
action\_result\.data\.\*\.result\.services\.\*\.transport\_fingerprint\.id | numeric | 
action\_result\.data\.\*\.result\.services\.\*\.transport\_fingerprint\.raw | string | 
action\_result\.data\.\*\.result\.services\.\*\.transport\_protocol | string | 
action\_result\.data\.\*\.result\.services\.\*\.truncated | boolean | 
action\_result\.data\.\*\.status | string | 
action\_result\.summary\.port | numeric | 
action\_result\.summary\.port | numeric | 
action\_result\.summary\.service\_name | string | 
action\_result\.summary\.service\_name | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Lookup Domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.alexa\_rank | numeric | 
action\_result\.data\.\*\.autonomous\_system\.asn | numeric | 
action\_result\.data\.\*\.autonomous\_system\.country\_code | string | 
action\_result\.data\.\*\.autonomous\_system\.description | string | 
action\_result\.data\.\*\.autonomous\_system\.name | string | 
action\_result\.data\.\*\.autonomous\_system\.organization | string | 
action\_result\.data\.\*\.autonomous\_system\.path | numeric | 
action\_result\.data\.\*\.autonomous\_system\.rir | string | 
action\_result\.data\.\*\.autonomous\_system\.routed\_prefix | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.location\.city | string | 
action\_result\.data\.\*\.location\.continent | string | 
action\_result\.data\.\*\.location\.country | string | 
action\_result\.data\.\*\.location\.country\_code | string | 
action\_result\.data\.\*\.location\.latitude | numeric | 
action\_result\.data\.\*\.location\.longitude | numeric | 
action\_result\.data\.\*\.location\.postal\_code | string | 
action\_result\.data\.\*\.location\.province | string | 
action\_result\.data\.\*\.location\.registered\_country | string | 
action\_result\.data\.\*\.location\.registered\_country\_code | string | 
action\_result\.data\.\*\.location\.timezone | string | 
action\_result\.data\.\*\.ports\.0\.lookup\.axfr\.servers\.\*\.error | string | 
action\_result\.data\.\*\.ports\.0\.lookup\.axfr\.servers\.\*\.server | string | 
action\_result\.data\.\*\.ports\.0\.lookup\.axfr\.servers\.\*\.status | string | 
action\_result\.data\.\*\.ports\.0\.lookup\.axfr\.support | boolean | 
action\_result\.data\.\*\.ports\.0\.lookup\.axfr\.truncated | boolean | 
action\_result\.data\.\*\.ports\.0\.lookup\.dmarc\.raw | string | 
action\_result\.data\.\*\.ports\.0\.lookup\.spf\.raw | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.banner | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.ehlo | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.metadata\.description | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.metadata\.manufacturer | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.metadata\.product | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.starttls | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.authority\_info\_access\.issuer\_urls | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.authority\_info\_access\.ocsp\_urls | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.authority\_key\_id | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.basic\_constraints\.is\_ca | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.crl\_distribution\_points | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.extended\_key\_usage | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.subject\_alt\_name\.dns\_names | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.extensions\.subject\_key\_id | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.fingerprint\_md5 | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.fingerprint\_sha1 | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.issuer\.common\_name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.issuer\.country | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.issuer\.organization | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.issuer\_dn | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.names | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.serial\_number | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\.self\_signed | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\.valid | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\.value | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.spki\_subject\_fingerprint | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\.common\_name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\.country | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\.locality | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\.organization | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\.province | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_dn | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_key\_info\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_key\_info\.key\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_key\_info\.key\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_key\_info\.rsa\_public\_key\.exponent | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_key\_info\.rsa\_public\_key\.length | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.subject\_key\_info\.rsa\_public\_key\.modulus | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.tbs\_fingerprint | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.tbs\_noct\_fingerprint | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.validation\_level | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.validity\.end | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.validity\.length | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.validity\.start | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.certificate\.parsed\.version | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.authority\_info\_access\.ocsp\_urls | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.authority\_key\_id | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.basic\_constraints\.is\_ca | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.basic\_constraints\.max\_path\_len | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.crl\_distribution\_points | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.key\_usage\.certificate\_sign | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.key\_usage\.crl\_sign | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.key\_usage\.value | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.extensions\.subject\_key\_id | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.fingerprint\_md5 | string |  `md5` 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.fingerprint\_sha1 | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.issuer\.common\_name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.issuer\.country | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.issuer\.organization | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.issuer\.organizational\_unit | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.issuer\_dn | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.serial\_number | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\.self\_signed | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\.valid | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\.value | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.spki\_subject\_fingerprint | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\.common\_name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\.country | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\.organization | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_dn | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_key\_info\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_key\_info\.key\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_key\_info\.key\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.exponent | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.length | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.modulus | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.tbs\_fingerprint | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.tbs\_noct\_fingerprint | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.validation\_level | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.validity\.end | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.validity\.length | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.validity\.start | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.chain\.\*\.parsed\.version | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.cipher\_suite\.id | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.cipher\_suite\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.ocsp\_stapling | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.server\_key\_exchange\.ecdh\_params\.curve\_id\.id | numeric | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.server\_key\_exchange\.ecdh\_params\.curve\_id\.name | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.signature\.hash\_algorithm | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.signature\.signature\_algorithm | string | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.signature\.valid | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.validation\.browser\_trusted | boolean | 
action\_result\.data\.\*\.ports\.25\.smtp\.starttls\.tls\.version | string | 
action\_result\.data\.\*\.ports\.443\.https\.dhe\.support | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.dhe\_export\.support | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.heartbleed\.heartbeat\_enabled | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.heartbleed\.heartbleed\_vulnerable | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.rsa\_export\.support | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.authority\_info\_access\.issuer\_urls | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.authority\_info\_access\.ocsp\_urls | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.authority\_key\_id | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.basic\_constraints\.is\_ca | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.crl\_distribution\_points | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.extended\_key\_usage | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.key\_usage\.digital\_signature | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.key\_usage\.value | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.subject\_alt\_name\.dns\_names | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.extensions\.subject\_key\_id | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.fingerprint\_md5 | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.fingerprint\_sha1 | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.issuer\.common\_name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.issuer\.country | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.issuer\.organization | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.issuer\_dn | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.names | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.serial\_number | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\.self\_signed | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\.valid | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\.value | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.spki\_subject\_fingerprint | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\.common\_name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\.country | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\.locality | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\.organization | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\.province | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_dn | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.b | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.gx | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.gy | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.n | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.p | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.pub | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.x | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.ecdsa\_public\_key\.y | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.key\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.subject\_key\_info\.key\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.tbs\_fingerprint | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.tbs\_noct\_fingerprint | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.validation\_level | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.validity\.end | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.validity\.length | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.validity\.start | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.certificate\.parsed\.version | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.authority\_info\_access\.ocsp\_urls | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.authority\_key\_id | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.basic\_constraints\.is\_ca | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.basic\_constraints\.max\_path\_len | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.certificate\_policies | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.crl\_distribution\_points | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.key\_usage\.certificate\_sign | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.key\_usage\.crl\_sign | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.key\_usage\.value | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.extensions\.subject\_key\_id | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.fingerprint\_md5 | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.fingerprint\_sha1 | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.issuer\.common\_name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.issuer\.country | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.issuer\.organization | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.issuer\.organizational\_unit | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.issuer\_dn | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.serial\_number | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\.self\_signed | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\.valid | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\.value | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.signature\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.spki\_subject\_fingerprint | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\.common\_name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\.country | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\.organization | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_dn | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_key\_info\.fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_key\_info\.key\_algorithm\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_key\_info\.key\_algorithm\.oid | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.exponent | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.length | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.subject\_key\_info\.rsa\_public\_key\.modulus | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.tbs\_fingerprint | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.tbs\_noct\_fingerprint | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.validation\_level | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.validity\.end | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.validity\.length | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.validity\.start | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.chain\.\*\.parsed\.version | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.cipher\_suite\.id | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.cipher\_suite\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.ocsp\_stapling | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.server\_key\_exchange\.ecdh\_params\.curve\_id\.id | numeric | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.server\_key\_exchange\.ecdh\_params\.curve\_id\.name | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.signature\.hash\_algorithm | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.signature\.signature\_algorithm | string | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.signature\.valid | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.validation\.browser\_trusted | boolean | 
action\_result\.data\.\*\.ports\.443\.https\.tls\.validation\.matches\_domain | boolean |  `domain` 
action\_result\.data\.\*\.ports\.443\.https\.tls\.version | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.body | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.body\_sha256 | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.cache\_control | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.content\_type | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.expires | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.p3p | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.server | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.unknown\.\*\.key | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.unknown\.\*\.value | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.x\_frame\_options | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.headers\.x\_xss\_protection | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.status\_code | numeric | 
action\_result\.data\.\*\.ports\.80\.http\.get\.status\_line | string | 
action\_result\.data\.\*\.ports\.80\.http\.get\.title | string | 
action\_result\.data\.\*\.protocols | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.updated\_at | string | 
action\_result\.summary\.protocols | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'query domain'
Query the domain dataset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Censys\.IO query string to use | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.alexa\_rank | numeric | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.summary\.result\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'query certificate'
Query the certificate dataset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Censys\.IO query string to use | string | 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.parsed\_fingerprint\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.parsed\_issuer\_dn | string | 
action\_result\.data\.\*\.parsed\_subject\_dn | string | 
action\_result\.summary\.result\_count | numeric | 
action\_result\.summary\.total\_available\_records | numeric | 
action\_result\.summary\.total\_records\_fetched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'query ip'
Query the IP dataset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Censys\.IO query string to use | string | 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.autonomous\_system\.asn | numeric | 
action\_result\.data\.\*\.autonomous\_system\.bgp\_prefix | string | 
action\_result\.data\.\*\.autonomous\_system\.country\_code | string | 
action\_result\.data\.\*\.autonomous\_system\.description | string | 
action\_result\.data\.\*\.autonomous\_system\.name | string | 
action\_result\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.location\.city | string | 
action\_result\.data\.\*\.location\.continent | string | 
action\_result\.data\.\*\.location\.coordinates\.latitude | numeric | 
action\_result\.data\.\*\.location\.coordinates\.longitude | numeric | 
action\_result\.data\.\*\.location\.country | string | 
action\_result\.data\.\*\.location\.country\_code | string | 
action\_result\.data\.\*\.location\.postal\_code | string | 
action\_result\.data\.\*\.location\.province | string | 
action\_result\.data\.\*\.location\.registered\_country | string | 
action\_result\.data\.\*\.location\.registered\_country\_code | string | 
action\_result\.data\.\*\.location\.timezone | string | 
action\_result\.data\.\*\.operating\_system\.part | string | 
action\_result\.data\.\*\.operating\_system\.product | string | 
action\_result\.data\.\*\.operating\_system\.source | string | 
action\_result\.data\.\*\.operating\_system\.uniform\_resource\_identifier | string | 
action\_result\.data\.\*\.operating\_system\.vendor | string | 
action\_result\.data\.\*\.operating\_system\.version | string | 
action\_result\.data\.\*\.services\.\*\.certificate | string | 
action\_result\.data\.\*\.services\.\*\.port | string | 
action\_result\.data\.\*\.services\.\*\.service\_name | string | 
action\_result\.data\.\*\.services\.\*\.transport\_protocol | string | 
action\_result\.summary\.total\_available\_records | numeric | 
action\_result\.summary\.total\_records\_fetched | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 