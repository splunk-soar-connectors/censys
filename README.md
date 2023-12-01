[comment]: # "Auto-generated SOAR connector documentation"
# Censys

Publisher: Splunk  
Connector Version: 2.2.1  
Product Vendor: Censys, Inc.  
Product Name: Censys  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

This app implements investigative actions to get information from the Censys search engine

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


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Censys asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_id** |  required  | password | API ID
**secret** |  required  | password | Secret

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate connectivity to Censys  
[lookup certificate](#action-lookup-certificate) - Lookup certificate info  
[lookup ip](#action-lookup-ip) - Lookup IP info  
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
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.sha256 | string |  `hash`  `sha256`  |   54c8df22f5307f78229f3fed069c67cdba9ed96a10332a2713abc427c1debbbf 
action_result.data.\*.audit.nss.is_in | boolean |  |   True  False 
action_result.data.\*.audit.nss.was_in | boolean |  |   True  False 
action_result.data.\*.ct.comodo_dodo.added_to_ct_at | string |  |   2018-09-10T20:39:13.358Z 
action_result.data.\*.ct.comodo_dodo.ct_to_censys_at | string |  |   2018-09-10T20:45:02.084909144Z 
action_result.data.\*.ct.comodo_dodo.index | numeric |  |   4520662 
action_result.data.\*.ct.digicert_ct1.added_to_ct_at | string |  |  
action_result.data.\*.ct.digicert_ct1.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.digicert_ct1.index | numeric |  |   22130687 
action_result.data.\*.ct.google_aviator.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_aviator.censys_to_ct_at | string |  |  
action_result.data.\*.ct.google_aviator.censys_to_ct_status | string |  |  
action_result.data.\*.ct.google_aviator.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_aviator.index | numeric |  |   22130687 
action_result.data.\*.ct.google_aviator.sct | string |  |  
action_result.data.\*.ct.google_pilot.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_pilot.censys_to_ct_at | string |  |  
action_result.data.\*.ct.google_pilot.censys_to_ct_status | string |  |  
action_result.data.\*.ct.google_pilot.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_pilot.index | numeric |  |   22130687 
action_result.data.\*.ct.google_pilot.sct | string |  |  
action_result.data.\*.ct.google_rocketeer.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_rocketeer.censys_to_ct_at | string |  |  
action_result.data.\*.ct.google_rocketeer.censys_to_ct_status | string |  |  
action_result.data.\*.ct.google_rocketeer.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_rocketeer.index | numeric |  |   22130687 
action_result.data.\*.ct.google_rocketeer.sct | string |  |  
action_result.data.\*.ct.google_submariner.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_submariner.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.google_submariner.index | numeric |  |   22130687 
action_result.data.\*.ct.symantec_ws_ct.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.symantec_ws_ct.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.symantec_ws_ct.index | numeric |  |   22130687 
action_result.data.\*.ct.symantec_ws_deneb.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.symantec_ws_deneb.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.symantec_ws_deneb.index | numeric |  |   22130687 
action_result.data.\*.ct.symantec_ws_vega.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.symantec_ws_vega.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.symantec_ws_vega.index | numeric |  |   22130687 
action_result.data.\*.ct.venafi_api_ctlog.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.venafi_api_ctlog.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.venafi_api_ctlog.index | numeric |  |   22130687 
action_result.data.\*.ct.wosign_ctlog.added_to_ct_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.wosign_ctlog.ct_to_censys_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.ct.wosign_ctlog.index | numeric |  |   22130687 
action_result.data.\*.current_in_nss | boolean |  |   True  False 
action_result.data.\*.current_valid_nss | boolean |  |   True  False 
action_result.data.\*.fingerprint_sha256 | string |  |   54c8df22f5307f78229f3fed069c67cdba9ed96a10332a2713abc427c1debbbf 
action_result.data.\*.in_nss | boolean |  |   True  False 
action_result.data.\*.metadata.added_at | string |  |   1970-01-01T00:00:00Z 
action_result.data.\*.metadata.parse_status | string |  |   success 
action_result.data.\*.metadata.parse_version | numeric |  |   1 
action_result.data.\*.metadata.post_processed | boolean |  |   True 
action_result.data.\*.metadata.post_processed_at | string |  |   2018-09-10T20:45:09Z 
action_result.data.\*.metadata.seen_in_scan | boolean |  |   False 
action_result.data.\*.metadata.source | string |  |   ct 
action_result.data.\*.metadata.updated_at | string |  |   2018-09-10T20:45:10Z 
action_result.data.\*.parent_spki_subject_fingerprint | string |  |   b761d93f79ebf6b87109a479e3583d167aed68378264548381ff11ba5fb19a47 
action_result.data.\*.parents | string |  |  
action_result.data.\*.parsed.extensions.authority_info_access.ocsp_urls | string |  |  
action_result.data.\*.parsed.extensions.authority_key_id | string |  |  
action_result.data.\*.parsed.extensions.basic_constraints.is_ca | boolean |  |   True  False 
action_result.data.\*.parsed.extensions.basic_constraints.max_path_len | numeric |  |  
action_result.data.\*.parsed.extensions.certificate_policies | string |  |  
action_result.data.\*.parsed.extensions.certificate_policies.\*.id | string |  |   2.23.140.1.2.2 
action_result.data.\*.parsed.extensions.certificate_policies.\*.user_notice.\*.explicit_text | string |  |   https://www.thawte.com/repository 
action_result.data.\*.parsed.extensions.crl_distribution_points | string |  |  
action_result.data.\*.parsed.extensions.ct_poison | boolean |  |   True 
action_result.data.\*.parsed.extensions.extended_key_usage.client_auth | boolean |  |   True 
action_result.data.\*.parsed.extensions.extended_key_usage.server_auth | boolean |  |   True 
action_result.data.\*.parsed.extensions.key_usage.certificate_sign | boolean |  |   True  False 
action_result.data.\*.parsed.extensions.key_usage.crl_sign | boolean |  |   True  False 
action_result.data.\*.parsed.extensions.key_usage.digital_signature | boolean |  |   True 
action_result.data.\*.parsed.extensions.key_usage.key_encipherment | boolean |  |   True 
action_result.data.\*.parsed.extensions.key_usage.value | numeric |  |  
action_result.data.\*.parsed.extensions.subject_alt_name.directory_names.\*.common_name | string |  |  
action_result.data.\*.parsed.extensions.subject_key_id | string |  |   736b5edbcfc9191d5bd01f8ce3ab5638189f024f 
action_result.data.\*.parsed.fingerprint_md5 | string |  |   950098276a495286eb2a2556fbab6d83 
action_result.data.\*.parsed.fingerprint_sha1 | string |  |   6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c 
action_result.data.\*.parsed.fingerprint_sha256 | string |  `sha256`  |   87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c 
action_result.data.\*.parsed.issuer.common_name | string |  |  
action_result.data.\*.parsed.issuer.country | string |  |  
action_result.data.\*.parsed.issuer.organization | string |  |  
action_result.data.\*.parsed.issuer.organizational_unit | string |  |  
action_result.data.\*.parsed.issuer_dn | string |  |  
action_result.data.\*.parsed.redacted | boolean |  |   True 
action_result.data.\*.parsed.serial_number | string |  |  
action_result.data.\*.parsed.signature.self_signed | boolean |  |   True  False 
action_result.data.\*.parsed.signature.signature_algorithm.name | string |  |  
action_result.data.\*.parsed.signature.signature_algorithm.oid | string |  |  
action_result.data.\*.parsed.signature.valid | boolean |  |   True  False 
action_result.data.\*.parsed.signature.value | string |  |  
action_result.data.\*.parsed.signature_algorithm.name | string |  |  
action_result.data.\*.parsed.signature_algorithm.oid | string |  |  
action_result.data.\*.parsed.spki_subject_fingerprint | string |  |  
action_result.data.\*.parsed.subject.common_name | string |  |  
action_result.data.\*.parsed.subject.country | string |  |  
action_result.data.\*.parsed.subject.organization | string |  |  
action_result.data.\*.parsed.subject.organizational_unit | string |  |  
action_result.data.\*.parsed.subject_dn | string |  |  
action_result.data.\*.parsed.subject_key_info.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.parsed.subject_key_info.key_algorithm.name | string |  |  
action_result.data.\*.parsed.subject_key_info.key_algorithm.oid | string |  |  
action_result.data.\*.parsed.subject_key_info.rsa_public_key.exponent | numeric |  |  
action_result.data.\*.parsed.subject_key_info.rsa_public_key.length | numeric |  |  
action_result.data.\*.parsed.subject_key_info.rsa_public_key.modulus | string |  |  
action_result.data.\*.parsed.tbs_fingerprint | string |  |  
action_result.data.\*.parsed.tbs_noct_fingerprint | string |  |  
action_result.data.\*.parsed.validation_level | string |  |  
action_result.data.\*.parsed.validity.end | string |  |  
action_result.data.\*.parsed.validity.length | numeric |  |  
action_result.data.\*.parsed.validity.start | string |  |  
action_result.data.\*.parsed.version | numeric |  |  
action_result.data.\*.post_processed | boolean |  |   True  False 
action_result.data.\*.precert | boolean |  |   True  False 
action_result.data.\*.raw | string |  |   MIIDIzCCAgugAwIBAgIECLsA7jANBgkqhkiG9w0BAQsFADBCMQkwBwYDVQQGEwAxCTAHBgNVBAgTADEJMAcGA1UEBxMAMQkwBwYDVQQKEwAxCTAHBgNVBAsTADEJMAcGA1UEAxMAMB4XDTE1MDUyMDE4MjYyNFoXDTI1MDUxNzE4MjYyNFowQjEJMAcGA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQLEwAxCTAHBgNVBAMTADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJjXGpNxjm97YowJUxMyM/QBjGTnyUqMXt1IsXArVdop3F/fGdhsmWkExTt8AfjWm9TL2I3KCVKqBhQ9U8+W+l3JAPNaqLnOqRSfeQ+SQ0tmLuVn1AVQt1RKYZGo+o70G/yAXBNwCQ3mUisLe6Ln926E3seZM6gb8HesF/w+2sCcQ2UaqLY3hKVIDYvlenNaNMxtaw+8A/3udT+pIX1JyrlIlt0SDg5Ya2opwYTFJM64KbuyDKkK213A5Sz00Rh13PVRKWlpfVtgoh9BNupzJOG/GE/x0XmXCYAOIGrm8uujAtUWJ5nkbaczf2ldnITJBw+3iQrtE1LEM8aUJeKRCVkCAwEAAaMhMB8wHQYDVR0OBBYEFHNrXtvPyRkdW9AfjOOrVjgYnwJPMA0GCSqGSIb3DQEBCwUAA4IBAQBU9S+o9YRFBTzcCeZ4phipmwJ9PsIFKoidgkTekbt3EzyL+Q+nySQ/Gn4ZXdliFYxKNcRmxbSWCa9jX6qJb6t7gcLBP8Hp7kWLsNdbk19+iSDphVfO6UdL6ZVIbIy0vNO0/LgEKVi7tzE84elcaS45ZSPY+HnySF2sP3SF0n9iF/bWdzYOjLcPpgavsT66KLrileXkYjCWFOXufnZgpf11pGd3wTJEIenSabc90LQ4rAvBJPicY/AfhIth/g4GiDG+M1DmzlV+1F0nNr3KuNGjeghLVegKoRq/b5PF+0kpSK7HUwIdrgZsqz1ORsMToEyv8LvxIyL0DTCLBJSHmgJy 
action_result.data.\*.seen_in_scan | boolean |  |   True  False 
action_result.data.\*.source | string |  |  
action_result.data.\*.updated_at | string |  |  
action_result.data.\*.valid_nss | boolean |  |   True  False 
action_result.data.\*.validation.apple.blacklisted | boolean |  |   False 
action_result.data.\*.validation.apple.had_trusted_path | boolean |  |   True 
action_result.data.\*.validation.apple.in_revocation_set | boolean |  |   False 
action_result.data.\*.validation.apple.trusted_path | boolean |  |   False 
action_result.data.\*.validation.apple.type | string |  |   leaf 
action_result.data.\*.validation.apple.valid | boolean |  |   False 
action_result.data.\*.validation.apple.was_valid | boolean |  |   True 
action_result.data.\*.validation.apple.whitelisted | boolean |  |   False 
action_result.data.\*.validation.google_ct_primary.blacklisted | boolean |  |   False 
action_result.data.\*.validation.google_ct_primary.had_trusted_path | boolean |  |   True 
action_result.data.\*.validation.google_ct_primary.in_revocation_set | boolean |  |   False 
action_result.data.\*.validation.google_ct_primary.trusted_path | boolean |  |   False 
action_result.data.\*.validation.google_ct_primary.type | string |  |   leaf 
action_result.data.\*.validation.google_ct_primary.valid | boolean |  |   False 
action_result.data.\*.validation.google_ct_primary.was_valid | boolean |  |   True 
action_result.data.\*.validation.google_ct_primary.whitelisted | boolean |  |   False 
action_result.data.\*.validation.microsoft.blacklisted | boolean |  |   False 
action_result.data.\*.validation.microsoft.had_trusted_path | boolean |  |   True 
action_result.data.\*.validation.microsoft.in_revocation_set | boolean |  |   False 
action_result.data.\*.validation.microsoft.trusted_path | boolean |  |   False 
action_result.data.\*.validation.microsoft.type | string |  |   leaf 
action_result.data.\*.validation.microsoft.valid | boolean |  |   False 
action_result.data.\*.validation.microsoft.was_valid | boolean |  |   True 
action_result.data.\*.validation.microsoft.whitelisted | boolean |  |   False 
action_result.data.\*.validation.nss.blacklisted | boolean |  |   False 
action_result.data.\*.validation.nss.had_trusted_path | boolean |  |   True 
action_result.data.\*.validation.nss.in_revocation_set | boolean |  |   False 
action_result.data.\*.validation.nss.trusted_path | boolean |  |   False 
action_result.data.\*.validation.nss.type | string |  |   leaf 
action_result.data.\*.validation.nss.valid | boolean |  |   False 
action_result.data.\*.validation.nss.was_valid | boolean |  |   True 
action_result.data.\*.validation.nss.whitelisted | boolean |  |   False 
action_result.data.\*.validation.revoked | boolean |  |   False 
action_result.data.\*.validation_timestamp | string |  |  
action_result.data.\*.was_in_nss | boolean |  |   True  False 
action_result.data.\*.was_valid_nss | boolean |  |   True  False 
action_result.data.\*.zlint.errors_present | boolean |  |   False 
action_result.data.\*.zlint.fatals_present | boolean |  |   False 
action_result.data.\*.zlint.lints.n_contains_redacted_dnsname | boolean |  |   True 
action_result.data.\*.zlint.lints.n_subject_common_name_included | boolean |  |   True 
action_result.data.\*.zlint.lints.w_ext_subject_key_identifier_missing_sub_cert | boolean |  |   True 
action_result.data.\*.zlint.notices_present | boolean |  |   True 
action_result.data.\*.zlint.version | numeric |  |   3 
action_result.data.\*.zlint.warnings_present | boolean |  |   True 
action_result.summary.issuer_dn | string |  |   C=, ST=, L=, O=, OU=, CN= 
action_result.summary.subject_dn | string |  |   C=, ST=, L=, O=, OU=, CN= 
action_result.summary.valid_from | string |  |   2015-05-20T18:26:24Z 
action_result.summary.valid_to | string |  |   2025-05-17T18:26:24Z 
action_result.message | string |  |   Valid from: 2015-05-20T18:26:24Z, Valid to: 2025-05-17T18:26:24Z, Issuer dn: C=, ST=, L=, O=, OU=, CN=, Subject dn: C=, ST=, L=, O=, OU=, CN= 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup ip'
Lookup IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to get info of | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  `ipv6`  |   3.0.0.8  2001:db8:3333:4444:5555:6666:7777:8888 
action_result.data.\*.443.https.dhe.support | boolean |  |   False 
action_result.data.\*.443.https.dhe_export.support | boolean |  |   False 
action_result.data.\*.443.https.rsa_export.support | boolean |  |   False 
action_result.data.\*.autonomous_system.asn | numeric |  |   13335 
action_result.data.\*.autonomous_system.country_code | string |  |   US 
action_result.data.\*.autonomous_system.description | string |  |   CLOUDFLARENET 
action_result.data.\*.autonomous_system.name | string |  |   CLOUDFLARENET 
action_result.data.\*.autonomous_system.rir | string |  |   unknown 
action_result.data.\*.autonomous_system.routed_prefix | string |  |   1.0.0.0/24 
action_result.data.\*.code | numeric |  |   200 
action_result.data.\*.ip | string |  `ip`  `ipv6`  |   1.0.0.0 
action_result.data.\*.location.continent | string |  |   Oceania 
action_result.data.\*.location.country | string |  |   Australia 
action_result.data.\*.location.country_code | string |  |   AU 
action_result.data.\*.location.latitude | numeric |  |   -33.494 
action_result.data.\*.location.longitude | numeric |  |   143.2104 
action_result.data.\*.location.registered_country | string |  |   Australia 
action_result.data.\*.location.registered_country_code | string |  |   AU 
action_result.data.\*.location.timezone | string |  |   Australia/Sydney 
action_result.data.\*.result.autonomous_system.asn | numeric |  |   16509 
action_result.data.\*.result.autonomous_system.bgp_prefix | string |  |   54.239.16.0/20 
action_result.data.\*.result.autonomous_system.country_code | string |  |   US 
action_result.data.\*.result.autonomous_system.description | string |  |   AMAZON-02 
action_result.data.\*.result.autonomous_system.name | string |  |   AMAZON-02 
action_result.data.\*.result.autonomous_system_updated_at | string |  |   2021-11-13T23:19:19.468779Z 
action_result.data.\*.result.dns.records.ec2-3-8-0-0.eu-west-2.compute.amazonaws.com.record_type | string |  |   A 
action_result.data.\*.result.dns.records.ec2-3-8-0-0.eu-west-2.compute.amazonaws.com.resolved_at | string |  |   2021-10-28T03:01:56.147559092Z 
action_result.data.\*.result.dns.records.origin-www.amazon.com.record_type | string |  |   A 
action_result.data.\*.result.dns.records.origin-www.amazon.com.resolved_at | string |  |   2021-11-17T13:16:34.532024359Z 
action_result.data.\*.result.ip | string |  `ip`  `ipv6`  |  
action_result.data.\*.result.last_updated_at | string |  |   2021-11-21T21:32:57.423Z 
action_result.data.\*.result.location.city | string |  |   Ashburn 
action_result.data.\*.result.location.continent | string |  |   North America 
action_result.data.\*.result.location.coordinates.latitude | numeric |  |   39.0469 
action_result.data.\*.result.location.coordinates.longitude | numeric |  |   -77.4903 
action_result.data.\*.result.location.country | string |  |   United States 
action_result.data.\*.result.location.country_code | string |  |   US 
action_result.data.\*.result.location.postal_code | string |  |   20149 
action_result.data.\*.result.location.province | string |  |   Virginia 
action_result.data.\*.result.location.registered_country | string |  |   United States 
action_result.data.\*.result.location.registered_country_code | string |  |   US 
action_result.data.\*.result.location.timezone | string |  |   America/New_York 
action_result.data.\*.result.location_updated_at | string |  |   2021-11-21T21:32:57.391059Z 
action_result.data.\*.result.operating_system.other.family | string |  |   Linux 
action_result.data.\*.result.operating_system.part | string |  |   o 
action_result.data.\*.result.operating_system.product | string |  |   Linux 
action_result.data.\*.result.operating_system.uniform_resource_identifier | string |  |   cpe:2.3:o:centos:centos:\*:\*:\*:\*:\*:\*:\*:\* 
action_result.data.\*.result.operating_system.vendor | string |  |   CentOS 
action_result.data.\*.result.services.\*._decoded | string |  |   http 
action_result.data.\*.result.services.\*._encoding.banner | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*._encoding.banner_hex | string |  |   DISPLAY_HEX 
action_result.data.\*.result.services.\*._encoding.certificate | string |  |   DISPLAY_HEX 
action_result.data.\*.result.services.\*.banner | string |  |   HTTP/1.1 404 Not Found
Server: Apache
Content-Type: text/html; charset=iso-8859-1
Date: <REDACTED>
Connection: close
Content-Length: 196 
action_result.data.\*.result.services.\*.banner_hex | string |  |   485454502f312e3120343034204e6f7420466f756e640a5365727665723a204170616368650a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d69736f2d383835392d310a446174653a203c52454441435445443e0a436f6e6e656374696f6e3a20636c6f73650a436f6e74656e742d4c656e6774683a20313936 
action_result.data.\*.result.services.\*.certificate | string |  |   5bf3d7e0e6927f773d5106c822c53f6f52c199f7eb1b3b8154b41f2924391c75 
action_result.data.\*.result.services.\*.extended_service_name | string |  |   HTTP 
action_result.data.\*.result.services.\*.http.request.headers._encoding.Accept | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.request.headers._encoding.User_Agent | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.request.method | string |  |   GET 
action_result.data.\*.result.services.\*.http.request.uri | string |  |   http://3.8.0.0/ 
action_result.data.\*.result.services.\*.http.response._encoding.body | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response._encoding.body_hash | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response._encoding.html_tags | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response._encoding.html_title | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.body | string |  |   <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
 
action_result.data.\*.result.services.\*.http.response.body_hash | string |  |   sha1:d64bae91091eda6a7532ebec06aa70893b79e1f8 
action_result.data.\*.result.services.\*.http.response.body_size | numeric |  |   196 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Accept_Ranges | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Cache_Control | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Connection | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Content_Length | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Content_Type | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Date | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Etag | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Expires | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Last_Modified | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Location | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Referrer_Policy | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Server | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Set_Cookie | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.Vary | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Content_Type_Options | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Frame_Options | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Hudson | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Jenkins | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Jenkins_Session | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Matomo_Request_Id | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.headers._encoding.X_Powered_By | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.http.response.html_title | string |  |   404 Not Found 
action_result.data.\*.result.services.\*.http.response.protocol | string |  |   HTTP/1.1 
action_result.data.\*.result.services.\*.http.response.status_code | numeric |  |   404 
action_result.data.\*.result.services.\*.http.response.status_reason | string |  |   Not Found 
action_result.data.\*.result.services.\*.mysql._encoding.auth_plugin_data | string |  |   DISPLAY_HEX 
action_result.data.\*.result.services.\*.mysql.auth_plugin_data | string |  |   062a65217653656b4e176341794c5b505753015900 
action_result.data.\*.result.services.\*.mysql.auth_plugin_name | string |  |   caching_sha2_password 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_COMPRESS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_CONNECT_ATTRS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_CONNECT_WITH_DB | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_DEPRECATED_EOF | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_FOUND_ROWS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_IGNORE_SIGPIPE | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_IGNORE_SPACE | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_INTERACTIVE | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_LOCAL_FILES | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_LONG_FLAG | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_LONG_PASSWORD | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_MULTI_RESULTS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_MULTI_STATEMENTS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_NO_SCHEMA | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_ODBC | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_PLUGIN_AUTH | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_PLUGIN_AUTH_LEN_ENC_CLIENT_DATA | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_PROTOCOL_41 | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_PS_MULTI_RESULTS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_RESERVED | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_SECURE_CONNECTION | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_SESSION_TRACK | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_SSL | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.capability_flags.CLIENT_TRANSACTIONS | boolean |  |   True 
action_result.data.\*.result.services.\*.mysql.character_set | numeric |  |   255 
action_result.data.\*.result.services.\*.mysql.connection_id | numeric |  |   7249 
action_result.data.\*.result.services.\*.mysql.error_code | numeric |  |   0 
action_result.data.\*.result.services.\*.mysql.protocol_version | numeric |  |   10 
action_result.data.\*.result.services.\*.mysql.server_version | string |  |   8.0.24 
action_result.data.\*.result.services.\*.mysql.status_flags.SERVER_STATUS_AUTOCOMMIT | boolean |  |   True 
action_result.data.\*.result.services.\*.observed_at | string |  |   2021-11-21T05:42:04.118450668Z 
action_result.data.\*.result.services.\*.perspective_id | string |  |   PERSPECTIVE_NTT 
action_result.data.\*.result.services.\*.port | numeric |  |   80 
action_result.data.\*.result.services.\*.service_name | string |  |   HTTP 
action_result.data.\*.result.services.\*.software.\*.other.family | string |  |   Apache 
action_result.data.\*.result.services.\*.software.\*.other.info | string |  |   (CentOS) PHP/7.4.26 
action_result.data.\*.result.services.\*.software.\*.part | string |  |   a 
action_result.data.\*.result.services.\*.software.\*.product | string |  |   HTTPD 
action_result.data.\*.result.services.\*.software.\*.source | string |  |   OSI_APPLICATION_LAYER 
action_result.data.\*.result.services.\*.software.\*.uniform_resource_identifier | string |  |   cpe:2.3:a:apache:http_server:\*:\*:\*:\*:\*:\*:\*:\* 
action_result.data.\*.result.services.\*.software.\*.vendor | string |  |   Apache 
action_result.data.\*.result.services.\*.software.\*.version | string |  |   2.0 
action_result.data.\*.result.services.\*.source_ip | string |  |   167.248.133.60 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.client_to_server_alg_group.cipher | string |  |   aes128-ctr 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.client_to_server_alg_group.compression | string |  |   none 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.client_to_server_alg_group.mac | string |  |   hmac-sha2-256 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.host_key_algorithm | string |  |   ecdsa-sha2-nistp256 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.kex_algorithm | string |  |   curve25519-sha256@libssh.org 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.server_to_client_alg_group.cipher | string |  |   aes128-ctr 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.server_to_client_alg_group.compression | string |  |   none 
action_result.data.\*.result.services.\*.ssh.algorithm_selection.server_to_client_alg_group.mac | string |  |   hmac-sha2-256 
action_result.data.\*.result.services.\*.ssh.endpoint_id._encoding.raw | string |  |   DISPLAY_UTF8 
action_result.data.\*.result.services.\*.ssh.endpoint_id.protocol_version | string |  |   2.0 
action_result.data.\*.result.services.\*.ssh.endpoint_id.raw | string |  |   SSH-2.0-OpenSSH_7.4 
action_result.data.\*.result.services.\*.ssh.endpoint_id.software_version | string |  |   OpenSSH_7.4 
action_result.data.\*.result.services.\*.ssh.kex_init_message.first_kex_follows | boolean |  |   False 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.b | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.gx | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.gy | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.n | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.p | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.x | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key._encoding.y | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.b | string |  |   WsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEs= 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.curve | string |  |   P-256 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.gx | string |  |   axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY= 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.gy | string |  |   T+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU= 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.length | numeric |  |   256 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.n | string |  |   /////wAAAAD//////////7zm+q2nF56E87nKwvxjJVE= 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.p | string |  |   /////wAAAAEAAAAAAAAAAAAAAAD///////////////8= 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.x | string |  |   q97beO8DGS0xwQKNolJ7umVQN3AIPWNhXVC7Dzx9SGM= 
action_result.data.\*.result.services.\*.ssh.server_host_key.ecdsa_public_key.y | string |  |   KNDegOYkRKWF7SQEJIiGTqTObRSIhjvUcRR9U4IJ0ug= 
action_result.data.\*.result.services.\*.ssh.server_host_key.fingerprint_sha256 | string |  |   421716b215b76be624b10596f3a12c5eb9148d1f92e07a15d9bb9f2f0a90f34c 
action_result.data.\*.result.services.\*.tls.certificates._encoding.chain_fps_sha_256 | string |  |   DISPLAY_HEX 
action_result.data.\*.result.services.\*.tls.certificates._encoding.leaf_fp_sha_256 | string |  |   DISPLAY_HEX 
action_result.data.\*.result.services.\*.tls.certificates.chain.\*.fingerprint | string |  |   8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b 
action_result.data.\*.result.services.\*.tls.certificates.chain.\*.issuer_dn | string |  |   C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2 
action_result.data.\*.result.services.\*.tls.certificates.chain.\*.subject_dn | string |  |   C=US, O=DigiCert Inc, CN=DigiCert Global CA G2 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.fingerprint | string |  |   5bf3d7e0e6927f773d5106c822c53f6f52c199f7eb1b3b8154b41f2924391c75 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.issuer_dn | string |  |   C=US, O=DigiCert Inc, CN=DigiCert Global CA G2 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.pubkey_algorithm | string |  |   RSA 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.pubkey_bit_size | numeric |  |   2048 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.fingerprint | string |  |   5dfb8a839c37dc0db3e129b0acefb50923a4d84931596890149e9f1c84baa8ac 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.key_algorithm | string |  |   RSA 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.rsa._encoding.exponent | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.rsa._encoding.modulus | string |  |   DISPLAY_BASE64 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.rsa.exponent | string |  |   AAEAAQ== 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.rsa.length | numeric |  |   256 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.public_key.rsa.modulus | string |  |   v+/uM8Nke+pDU6lWoZALXfrNwH6/B3+8FEfNewD6mN8untzCMH8fPU5Gb1/odQWS7GiBPowoU6smFj4F0kD3Qh4OUpAVbcYS2ad5nVBnwmh8Tm/U3DO34FZgxtjz3qxBVKr1ryYO3+1/H2xBuit8W1TSd/s+2joupzAAQq0zn8B36kpi14dYIaZgBw0WuQHaybTlC0cko9x2t43RXxNZgRxqYyh+I+MK19ZOAZgCPAooJXyQiUIohTdOw8gnDY5gI4zhHyzvuhifSBeII1WA6MfGdiKV+K0R9LLr0oHYV3F7yCQoDN29ZVgXj4UZu64IxIQnuHRN6X2otR3qgUjAoQ== 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.signature.self_signed | boolean |  |   False 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.signature.signature_algorithm | string |  |   SHA256-RSA 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.subject_dn | string |  |   CN=\*.peg.a2z.com 
action_result.data.\*.result.services.\*.tls.certificates.leaf_data.tbs_fingerprint | string |  |   787c8b32c43d57cf862530a5a0af775b55cc98bf5e04edaf65753a68b3f3ea05 
action_result.data.\*.result.services.\*.tls.certificates.leaf_fp_sha_256 | string |  |   5bf3d7e0e6927f773d5106c822c53f6f52c199f7eb1b3b8154b41f2924391c75 
action_result.data.\*.result.services.\*.tls.cipher_selected | string |  |   TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 
action_result.data.\*.result.services.\*.tls.server_key_exchange.ec_params.named_curve | numeric |  |   23 
action_result.data.\*.result.services.\*.tls.session_ticket.length | numeric |  |   176 
action_result.data.\*.result.services.\*.tls.session_ticket.lifetime_hint | numeric |  |   43200 
action_result.data.\*.result.services.\*.tls.version_selected | string |  |   TLSv1_2 
action_result.data.\*.result.services.\*.transport_fingerprint.id | numeric |  |   0 
action_result.data.\*.result.services.\*.transport_fingerprint.raw | string |  |   28960,64,true,MSTNW,1424,false,false 
action_result.data.\*.result.services.\*.transport_protocol | string |  |   TCP 
action_result.data.\*.result.services.\*.truncated | boolean |  |   False 
action_result.data.\*.status | string |  |   OK 
action_result.summary.port | numeric |  |   80 
action_result.summary.port | numeric |  |   80 
action_result.summary.service_name | string |  |   HTTP 
action_result.summary.service_name | numeric |  |   HTTP 
action_result.message | string |  |   Port: 80, Service name: HTTP 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'lookup domain'
Lookup Domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.domain | string |  `domain`  |  
action_result.data.\*.alexa_rank | numeric |  |  
action_result.data.\*.autonomous_system.asn | numeric |  |  
action_result.data.\*.autonomous_system.country_code | string |  |  
action_result.data.\*.autonomous_system.description | string |  |  
action_result.data.\*.autonomous_system.name | string |  |  
action_result.data.\*.autonomous_system.organization | string |  |  
action_result.data.\*.autonomous_system.path | numeric |  |  
action_result.data.\*.autonomous_system.rir | string |  |  
action_result.data.\*.autonomous_system.routed_prefix | string |  |  
action_result.data.\*.domain | string |  `domain`  |  
action_result.data.\*.location.city | string |  |  
action_result.data.\*.location.continent | string |  |  
action_result.data.\*.location.country | string |  |  
action_result.data.\*.location.country_code | string |  |  
action_result.data.\*.location.latitude | numeric |  |  
action_result.data.\*.location.longitude | numeric |  |  
action_result.data.\*.location.postal_code | string |  |  
action_result.data.\*.location.province | string |  |  
action_result.data.\*.location.registered_country | string |  |  
action_result.data.\*.location.registered_country_code | string |  |  
action_result.data.\*.location.timezone | string |  |  
action_result.data.\*.ports.0.lookup.axfr.servers.\*.error | string |  |  
action_result.data.\*.ports.0.lookup.axfr.servers.\*.server | string |  |  
action_result.data.\*.ports.0.lookup.axfr.servers.\*.status | string |  |  
action_result.data.\*.ports.0.lookup.axfr.support | boolean |  |  
action_result.data.\*.ports.0.lookup.axfr.truncated | boolean |  |  
action_result.data.\*.ports.0.lookup.dmarc.raw | string |  |  
action_result.data.\*.ports.0.lookup.spf.raw | string |  |  
action_result.data.\*.ports.25.smtp.starttls.banner | string |  |  
action_result.data.\*.ports.25.smtp.starttls.ehlo | string |  |  
action_result.data.\*.ports.25.smtp.starttls.metadata.description | string |  |  
action_result.data.\*.ports.25.smtp.starttls.metadata.manufacturer | string |  |  
action_result.data.\*.ports.25.smtp.starttls.metadata.product | string |  |  
action_result.data.\*.ports.25.smtp.starttls.starttls | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.authority_info_access.issuer_urls | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.authority_info_access.ocsp_urls | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.authority_key_id | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.basic_constraints.is_ca | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.certificate_policies | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.crl_distribution_points | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.extended_key_usage | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.subject_alt_name.dns_names | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.extensions.subject_key_id | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.fingerprint_md5 | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.fingerprint_sha1 | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.issuer.common_name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.issuer.country | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.issuer.organization | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.issuer_dn | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.names | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.serial_number | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature.self_signed | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature.signature_algorithm.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature.valid | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature.value | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature_algorithm.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.spki_subject_fingerprint | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject.common_name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject.country | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject.locality | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject.organization | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject.province | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_dn | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_key_info.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_key_info.key_algorithm.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_key_info.key_algorithm.oid | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_key_info.rsa_public_key.exponent | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_key_info.rsa_public_key.length | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.subject_key_info.rsa_public_key.modulus | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.tbs_fingerprint | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.tbs_noct_fingerprint | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.validation_level | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.validity.end | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.validity.length | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.validity.start | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.certificate.parsed.version | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.authority_info_access.ocsp_urls | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.authority_key_id | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.basic_constraints.is_ca | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.basic_constraints.max_path_len | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.certificate_policies | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.crl_distribution_points | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.key_usage.certificate_sign | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.key_usage.crl_sign | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.key_usage.value | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.extensions.subject_key_id | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.fingerprint_md5 | string |  `md5`  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.fingerprint_sha1 | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.issuer.common_name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.issuer.country | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.issuer.organization | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.issuer.organizational_unit | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.issuer_dn | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.serial_number | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature.self_signed | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature.signature_algorithm.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature.valid | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature.value | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature_algorithm.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.spki_subject_fingerprint | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject.common_name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject.country | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject.organization | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_dn | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_key_info.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_key_info.key_algorithm.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_key_info.key_algorithm.oid | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_key_info.rsa_public_key.exponent | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_key_info.rsa_public_key.length | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.subject_key_info.rsa_public_key.modulus | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.tbs_fingerprint | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.tbs_noct_fingerprint | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.validation_level | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.validity.end | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.validity.length | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.validity.start | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.chain.\*.parsed.version | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.cipher_suite.id | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.cipher_suite.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.ocsp_stapling | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.server_key_exchange.ecdh_params.curve_id.id | numeric |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.server_key_exchange.ecdh_params.curve_id.name | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.signature.hash_algorithm | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.signature.signature_algorithm | string |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.signature.valid | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.validation.browser_trusted | boolean |  |  
action_result.data.\*.ports.25.smtp.starttls.tls.version | string |  |  
action_result.data.\*.ports.443.https.dhe.support | boolean |  |  
action_result.data.\*.ports.443.https.dhe_export.support | boolean |  |  
action_result.data.\*.ports.443.https.heartbleed.heartbeat_enabled | boolean |  |  
action_result.data.\*.ports.443.https.heartbleed.heartbleed_vulnerable | boolean |  |  
action_result.data.\*.ports.443.https.rsa_export.support | boolean |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.authority_info_access.issuer_urls | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.authority_info_access.ocsp_urls | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.authority_key_id | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.basic_constraints.is_ca | boolean |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.certificate_policies | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.crl_distribution_points | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.extended_key_usage | numeric |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.key_usage.digital_signature | boolean |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.key_usage.value | numeric |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.extensions.subject_key_id | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.fingerprint_md5 | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.fingerprint_sha1 | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.issuer.common_name | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.issuer.country | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.issuer.organization | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.issuer_dn | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.names | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.serial_number | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature.self_signed | boolean |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature.signature_algorithm.name | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature.valid | boolean |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature.value | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature_algorithm.name | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.spki_subject_fingerprint | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject.common_name | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject.country | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject.locality | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject.organization | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject.province | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_dn | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.b | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.gx | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.gy | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.n | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.p | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.pub | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.x | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.ecdsa_public_key.y | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.key_algorithm.name | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.subject_key_info.key_algorithm.oid | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.tbs_fingerprint | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.tbs_noct_fingerprint | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.validation_level | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.validity.end | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.validity.length | numeric |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.validity.start | string |  |  
action_result.data.\*.ports.443.https.tls.certificate.parsed.version | numeric |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.authority_info_access.ocsp_urls | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.authority_key_id | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.basic_constraints.is_ca | boolean |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.basic_constraints.max_path_len | numeric |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.certificate_policies | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.crl_distribution_points | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.key_usage.certificate_sign | boolean |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.key_usage.crl_sign | boolean |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.key_usage.value | numeric |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.extensions.subject_key_id | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.fingerprint_md5 | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.fingerprint_sha1 | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.issuer.common_name | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.issuer.country | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.issuer.organization | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.issuer.organizational_unit | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.issuer_dn | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.serial_number | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature.self_signed | boolean |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature.signature_algorithm.name | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature.valid | boolean |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature.value | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature_algorithm.name | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.signature_algorithm.oid | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.spki_subject_fingerprint | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject.common_name | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject.country | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject.organization | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_dn | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_key_info.fingerprint_sha256 | string |  `sha256`  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_key_info.key_algorithm.name | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_key_info.key_algorithm.oid | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_key_info.rsa_public_key.exponent | numeric |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_key_info.rsa_public_key.length | numeric |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.subject_key_info.rsa_public_key.modulus | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.tbs_fingerprint | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.tbs_noct_fingerprint | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.validation_level | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.validity.end | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.validity.length | numeric |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.validity.start | string |  |  
action_result.data.\*.ports.443.https.tls.chain.\*.parsed.version | numeric |  |  
action_result.data.\*.ports.443.https.tls.cipher_suite.id | string |  |  
action_result.data.\*.ports.443.https.tls.cipher_suite.name | string |  |  
action_result.data.\*.ports.443.https.tls.ocsp_stapling | boolean |  |  
action_result.data.\*.ports.443.https.tls.server_key_exchange.ecdh_params.curve_id.id | numeric |  |  
action_result.data.\*.ports.443.https.tls.server_key_exchange.ecdh_params.curve_id.name | string |  |  
action_result.data.\*.ports.443.https.tls.signature.hash_algorithm | string |  |  
action_result.data.\*.ports.443.https.tls.signature.signature_algorithm | string |  |  
action_result.data.\*.ports.443.https.tls.signature.valid | boolean |  |  
action_result.data.\*.ports.443.https.tls.validation.browser_trusted | boolean |  |  
action_result.data.\*.ports.443.https.tls.validation.matches_domain | boolean |  `domain`  |  
action_result.data.\*.ports.443.https.tls.version | string |  |  
action_result.data.\*.ports.80.http.get.body | string |  |  
action_result.data.\*.ports.80.http.get.body_sha256 | string |  |  
action_result.data.\*.ports.80.http.get.headers.cache_control | string |  |  
action_result.data.\*.ports.80.http.get.headers.content_type | string |  |  
action_result.data.\*.ports.80.http.get.headers.expires | string |  |  
action_result.data.\*.ports.80.http.get.headers.p3p | string |  |  
action_result.data.\*.ports.80.http.get.headers.server | string |  |  
action_result.data.\*.ports.80.http.get.headers.unknown.\*.key | string |  |  
action_result.data.\*.ports.80.http.get.headers.unknown.\*.value | string |  |  
action_result.data.\*.ports.80.http.get.headers.x_frame_options | string |  |  
action_result.data.\*.ports.80.http.get.headers.x_xss_protection | string |  |  
action_result.data.\*.ports.80.http.get.status_code | numeric |  |  
action_result.data.\*.ports.80.http.get.status_line | string |  |  
action_result.data.\*.ports.80.http.get.title | string |  |  
action_result.data.\*.protocols | string |  |  
action_result.data.\*.tags | string |  |  
action_result.data.\*.updated_at | string |  |  
action_result.summary.protocols | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'query domain'
Query the domain dataset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Censys.IO query string to use | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.query | string |  |   not 443.https.tls.validation.browser_trusted: true 
action_result.data.\*.alexa_rank | numeric |  |   6 
action_result.data.\*.domain | string |  `domain`  |   qq.com 
action_result.summary.result_count | numeric |  |   671494 
action_result.message | string |  |   Result count: 671494 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'query certificate'
Query the certificate dataset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Censys.IO query string to use | string | 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   200 
action_result.parameter.query | string |  |   parsed.fingerprint_sha256: 87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c  ```(google.com\*) AND parsed.issuer.organization.raw:"Let's Encrypt"``` 
action_result.data.\*.parsed_fingerprint_sha256 | string |  `sha256`  |   87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c  1edb2d05b4b0008245356556c2ffe7a48e131639f50be49b311241de61a409fe 
action_result.data.\*.parsed_issuer_dn | string |  |   C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3 
action_result.data.\*.parsed_subject_dn | string |  |   CN=ghs.com.sommervillepartners.co.uk 
action_result.summary.result_count | numeric |  |   1  8632 
action_result.summary.total_available_records | numeric |  |   15000 
action_result.summary.total_records_fetched | numeric |  |   200 
action_result.message | string |  |   Total records fetched: 200, Total available records: 15000 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'query ip'
Query the IP dataset

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Censys.IO query string to use | string | 
**limit** |  optional  | Number of results to fetch | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   200 
action_result.parameter.query | string |  |   ports:22 and tags:camera 
action_result.data.\*.autonomous_system.asn | numeric |  |   45528 
action_result.data.\*.autonomous_system.bgp_prefix | string |  |   1.22.124.0/24 
action_result.data.\*.autonomous_system.country_code | string |  |   IN 
action_result.data.\*.autonomous_system.description | string |  |   TIKONAIN-AS Tikona Infinet Ltd. 
action_result.data.\*.autonomous_system.name | string |  |   TIKONAIN-AS Tikona Infinet Ltd. 
action_result.data.\*.ip | string |  `ip`  `ipv6`  |   80.15.120.40 
action_result.data.\*.location.city | string |  |   Provins 
action_result.data.\*.location.continent | string |  |   Europe 
action_result.data.\*.location.coordinates.latitude | numeric |  |   48.55 
action_result.data.\*.location.coordinates.longitude | numeric |  |   3.3 
action_result.data.\*.location.country | string |  |   France 
action_result.data.\*.location.country_code | string |  |   FR 
action_result.data.\*.location.postal_code | string |  |   77160 
action_result.data.\*.location.province | string |  |   Île-de-France 
action_result.data.\*.location.registered_country | string |  |   France 
action_result.data.\*.location.registered_country_code | string |  |   FR 
action_result.data.\*.location.timezone | string |  |   Europe/Paris 
action_result.data.\*.operating_system.part | string |  |   o 
action_result.data.\*.operating_system.product | string |  |   linux 
action_result.data.\*.operating_system.source | string |  |   OSI_TRANSPORT_LAYER 
action_result.data.\*.operating_system.uniform_resource_identifier | string |  |   cpe:2.3:o:\*:linux:\*:\*:\*:\*:\*:\*:\*:\* 
action_result.data.\*.operating_system.vendor | string |  |   MikroTik 
action_result.data.\*.operating_system.version | string |  |   6.45.9 
action_result.data.\*.services.\*.certificate | string |  |   bb3ea7cf4847dc16bad51d70a3a62952682f044cba7600f8c832f9e18b4a70bf 
action_result.data.\*.services.\*.port | string |  |   22/ssh 
action_result.data.\*.services.\*.service_name | string |  |   HTTP 
action_result.data.\*.services.\*.transport_protocol | string |  |   TCP 
action_result.summary.total_available_records | numeric |  |   15000 
action_result.summary.total_records_fetched | numeric |  |   200 
action_result.message | string |  |   Total records fetched: 200, Total available records: 15000 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 