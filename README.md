# Python3 Simple Metadefender framework.

## Description:
This framework used to interact with [OPSWAT Metadefender](https://metadefender.opswat.com/) security suite.

## Features:
This framework is used to:
- [x] Scan files by hash (SHA-256);
- [x] Scan files by binnaries;
- [x] Scan IP addresses;
- [ ] Scan domains;
- [ ] Scan URLs.

## Limitations:
Framework is not a complete solution ready out-of-the-box. By itself, its supposed to provide simple interface, and not pretend to be something more.
Usage limitations:
- [ ] Require OPSWAT Metadefender API key;
- [ ] Require [3-d party Python ```requests``` package](https://github.com/psf/requests) (free, open source).

## Usage:
### Quick example:
To use this framework, one have to solve dependencies:
```
pip install -r requirements.txt
```
When dependencies solved, simply use:
```
import metadefender

metadefender_framework = metadefender.Metadefender(apikey = API_Key)
ip_scan = metadefender_framework.scan_ip('1.2.3.4') # return `dict` type.
print(ip_scan)
```
```API_key``` is a OPSWAT Metadefender API, freely available on [it's site](https://metadefender.opswat.com/). Free API key is limited to 10 scan\day.

Available functions:
1. ```scan_ip```;
2. ```scan_file```;
3. ```scan_hash```.

### IP scan details:

If IP was never scanned or treat not detected, return empty ```dict```.
Else return dictionary with AV name and threat name.

For example, using ```metadefender_framework.scan_ip('1.2.3.4')``` (considering ```1.2.3.4``` is malicious) will return ```dict``` type data:
```
{
    scan_data = {
        "IP_spam_base": "Botnet_ip",
        "Another-base": "Spam_detected"
    }
    geo_data = {
        "Country": "...",
        "Region": "...",
        "City": "...",
        "Coordinates": {
            "Latitude": 123,
            "Longitude": 456
            }
    }
}
 ```
It uses a OPSWAT Metadefender APIv4 for perform scan.
(link: ```https://api.metadefender.com/v4/scan/```, HTTP GET requests).
Default succeed scan HTTP response code is 200;
If HTTP code is 429, too many scan attempts made or rate limit received.

### File scan details:
There are 2 methods of file scan: by binnary and by hash.
Scanning file by hash is prefered, as it quicker.
#### Scan by binnary:
```scan_file``` is used to scan file by binnary.

For example, using ```metadefender_framework.scan_file('/home/user/eicar.virus')``` (considering ```eicar.virus``` is "malicious" test file) will return **two** ```dict``` type data (same as ```scan_hash```), scan results:
```
{
    "ClamAV": "eicar test file",
    "Another-AV": "eicar:DOS",
    "...": "..."
}
 ```
 And scan details:
 ```
{
    "Total_Scanners": 42,
    "...": "..."
}
 ```
It uses a OPSWAT Metadefender APIv4 for perform scan (link: ```https://api.metadefender.com/v4/scan/```, HTTP GET requests).
Default succeed scan HTTP response code is 200;
If HTTP code is 429, too many scan attempts made or rate limit received.

#### Scan by hash:
```scan_hash``` is used to scan file by hash (SHA-256).

For example, using ```metadefender_framework.scan_hash('/home/user/eicar.virus')``` (considering ```eicar.virus``` is "malicious" test file) will return **two** ```dict``` type data (same as ```scan_file```), scan results:
```
{
    "ClamAV": "eicar test file",
    "Another-AV": "eicar:DOS",
    "...": "..."
}
 ```
 And scan details:
 ```
{
    "Total_Scanners": 42,
    "...": "..."
}
 ```
It uses a OPSWAT Metadefender APIv4 for perform scan (link: ```https://api.metadefender.com/v4/scan/```, HTTP GET requests).
Default succeed scan HTTP response code is 200;
If HTTP code is 429, too many scan attempts made or rate limit received.

# References:
For more information on used resources, follow:
- [Python IDE](https://www.python.org/)
- [Python ```requests``` package](https://github.com/psf/requests)
- [OPSWAT Metadefender](https://metadefender.opswat.com/)
