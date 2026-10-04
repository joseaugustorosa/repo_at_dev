# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 3 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 1    |
| Info | Informational | http://host.docker.internal:8000 | Percentage of responses with status code 2xx | 28 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of responses with status code 4xx | 71 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with content type application/json | 100 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method DELETE | 4 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method GET | 57 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method PATCH | 4 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method POST | 28 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method PUT | 4 % |
| Info | Informational | http://host.docker.internal:8000 | Count of total endpoints | 21    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| A Client Error response code was returned by the server | Informational | 15 |
| Authentication Request Identified | Informational | 1 |
| Non-Storable Content | Informational | Systemic |




## Alert Detail



### [ A Client Error response code was returned by the server ](https://www.zaproxy.org/docs/alerts/100000/)



##### Informational (High)

### Description

A response code of 422 was returned by the server.
This may indicate that the application is failing to handle unexpected input correctly.
Raised by the 'Alert on HTTP Response Code Error' script

* URL: http://host.docker.internal:8000/appointment/10
  * Node Name: `http://host.docker.internal:8000/appointment/10`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/appointment/%3Fstatus=&date_from=&date_to=&limit=50&offset=0
  * Node Name: `http://host.docker.internal:8000/appointment/ (date_from,date_to,limit,offset,status)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/appointment/10
  * Node Name: `http://host.docker.internal:8000/appointment/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/appointment/agenda%3Fday=
  * Node Name: `http://host.docker.internal:8000/appointment/agenda (day)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/availability/%3Fprofessional_id=10&day=day
  * Node Name: `http://host.docker.internal:8000/availability/ (day,professional_id)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/patient/10
  * Node Name: `http://host.docker.internal:8000/patient/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/%3Flimit=50&offset=0
  * Node Name: `http://host.docker.internal:8000/user/ (limit,offset)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/10/deactivate
  * Node Name: `http://host.docker.internal:8000/user/10/deactivate`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/appointment/new
  * Node Name: `http://host.docker.internal:8000/appointment/new ()({patient_id,date_time,reason,notes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/oauth/token
  * Node Name: `http://host.docker.internal:8000/oauth/token ()(client_id,client_secret,grant_type,scope)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/patient/new
  * Node Name: `http://host.docker.internal:8000/patient/new ()({"name":"ZAP","cpf":"John Doe","phone":"9999999999","email":zaproxy@example.com,"professional_id":10})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/mfa/verify
  * Node Name: `http://host.docker.internal:8000/user/mfa/verify ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/signin
  * Node Name: `http://host.docker.internal:8000/user/signin ()(client_id,client_secret,grant_type,password,scope,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/signup
  * Node Name: `http://host.docker.internal:8000/user/signup ()({name,email,password,role})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/appointment/10
  * Node Name: `http://host.docker.internal:8000/appointment/10 ()({date_time,reason,notes,status})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``


Instances: 15

### Solution



### Reference



#### CWE Id: [ 388 ](https://cwe.mitre.org/data/definitions/388.html)


#### WASC Id: 20

#### Source ID: 4

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://host.docker.internal:8000/user/signin
  * Node Name: `http://host.docker.internal:8000/user/signin ()(client_id,client_secret,grant_type,password,scope,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=username
passwordParam=password`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://host.docker.internal:8000/openapi.json
  * Node Name: `http://host.docker.internal:8000/openapi.json`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/me
  * Node Name: `http://host.docker.internal:8000/user/me`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/mfa/verify
  * Node Name: `http://host.docker.internal:8000/user/mfa/verify ()({mfa_token,code})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/signin
  * Node Name: `http://host.docker.internal:8000/user/signin ()(client_id,client_secret,grant_type,password,scope,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/user/signup
  * Node Name: `http://host.docker.internal:8000/user/signup ()({name,email,password,role})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


