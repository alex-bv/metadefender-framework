from hashlib import sha256 as get_sha256
import json
import os
import time
import logging

import requests


class Metadefender():
    """ OPSWAT Metadefender security scanner class.
    Receive Metadefender API key.

    Available methods:
        public: scan_ip, scan_file, scan_hash
        private: __request_file_scan_report, __check_response_data, __get_hash, __http_code_check, __parse_scan_report

    Required packages (dependencies): 
        built-in: hashlib, os, time, json
        3-d party: requests

    Use REST-API for communicate with Metadefender.

    OPSWAT official site (2018): www.opswat.com
    Metadefender official site (2018): metadefender.opswat.com

    Function relationship:

        scan_ip

        scan_file --> __request_file_scan_report -+
            |                                     |
            +-------> __check_response_data       |
            |                                     |
        scan_hash --> __get_hash                  |
            |                                     |
            +-------> __http_code_check <---------+
            |                                     |
            +-------> __parse_scan_report <-------+
    """

    def __init__(self, apikey, logging_level = 30):
        """ API key might be found on official OPSWAT site: opswat.com

        'apikey' - Metadefender API key;
        'logging_level' - verbosity of logging:
            0 - debug,
            30 - warnings,
            50 - critical.
            See 'logging' docs;
        """

        logging.basicConfig(level = logging_level,
                            filemode = 'a',
                            format='%(asctime)s >> %(name)s - %(levelname)s: %(message)s',
                            datefmt='%d.%m.%Y %H:%M:%S')

        self.MetaLog = logging.getLogger('Metadefender')
        self.MetaLog.debug('__init__: Initializing class...')

        if len(apikey) != 32:
            self.MetaLog.critical('__init__: Metadefender API key is incorrect.')
            self.MetaLog.debug('__init__: API key length is incorrect ({} instead of 32).'.format(len(apikey)))
            raise ValueError('Wrong API key.', apikey)
        else:
            self.MetaLog.debug('__init__: Metadefender API key length is OK.')
            self.apikey = apikey

        # Scan results response codes, see 'scan_result_i' or something like that.
        self._scan_result_keys = {
            -1: 'Scan not started',
            0: 'No Threats Found',
            1: 'Infected/Known',
            2: 'Suspicious',
            3: 'Failed To Scan',
            4: 'Cleaned/Deleted',
            5: 'Unknown',
            6: 'Quarantined',
            7: 'Skipped Clean',
            8: 'Skipped Infected',
            9: 'Exceeded Archive Depth',
            10: 'Not Scanned/No scan results',
            11: 'Aborted',
            12: 'Encrypted',
            13: 'Exceeded Archive Size',
            14: 'Exceeded Archive File Number',
            15: 'Password Protected Document',
            16: 'Exceeded Archive Timeout',
            17: 'Mismatch',
            18: 'Potentially Vulnerable File'
        }

        # HTTP response codes
        self._http_status_codes = {
            200: { # OK results
                "Status": "OK",
                "Description": "The request has succeeded",
                "Logging": 20 # See 'Logging Levels', 20 - INFO, 30 - Warning, 40 - Error, 50 - Critical
            },
            204: {
                "Status": "No Content",
                "Description": "The request has succeeded but it was a HEAD request",
                "Logging": 20
            },
            301: { # Link movement, not a error
                "Status": "Moved Permanently",
                "Description": "The endpoint was moved",
                "Logging": 40
            },
            400: { # Client-side errors
                "Status": "Bad Request", # Depreciated, see Metadefender respond error codes (self._metadefender_error_codes)
                "Description": "Client error",
                "Logging": 50
            },
            401: {
                "Status": "Not Authorized",
                "Description": "Authentication failed",
                "Logging": 50
            },
            404: {
                "Status": "Not Found",
                "Description": "Endpoint/entity was not found",
                "Logging": 40
            },
            405: {
                "Status": "Method Not Allowed",
                "Description": "CORS configuration missing",
                "Logging": 40
            },
            406: {
                "Status": "Not Acceptable",
                "Description": "Payload type is not accepted",
                "Logging": 40
            },
            408: {
                "Status": "Request Timeout",
                "Description": "The request was over 60 seconds",
                "Logging": 30
            },
            429: {
                "Status": "Too Many Requests",
                "Description": "Rate limit exceeded or too many requests per second",
                "Logging": 30
            },
            500: { # Server-side errors
                "Status": "Internal Server Error",
                "Description": "Something went wrong with the API",
                "Logging": 50
            },
            501: {
                "Status": "Not Implemented",
                "Description": "CORS method is not implemented",
                "Logging": 40
            },
            503: {
                "Status": "Service Unavailable",
                "Description": "3rd party service is not available",
                "Logging": 50
            }
        }

        ## Metadefender respond error codes, NOT EQUAL TO HTTP CODES.
        self._metadefender_error_codes = {
            "Generic": {
                "400000": "Generic error",
                "400001": "The caching strategy is not recognized",
                "400002": "The limit strategy is not supported",
                "400003": "The limit type is not supported",
                "400004": "The query parameters are not valid"
            },
            "Payload Validation": {
                "400020": "Header is not valid",
                "400021": "Body parsing failed",
                "400022": "Payload validation has failed",
                "400023": "Headers are not correct",
                "400024": "Headers are missing",
                "400025": "Payload is missing or empty",
                "400026": "Hash in the URL doesn't match the hash value in the body",
                "400027": "Offset should be a positive integer",
                "400028": "'Limit should be a positive integer less than 10, 000'"
            },
            "Routing Errors": {
                "400040": "The requested path is not valid",
                "400041": "The version is required",
                "400042": "The version does not exist",
                "400043": "The requested path does not exist",
                "400044": "Method does not exist",
                "400045": "The route was not properly set up",
                "400046": "The requested route does not exist",
                "400047": "This route is available only on development environments"
            },
            "Hash Errors": {
                "400060": "The `hash` field in the body is required",
                "400061": "The `hash` field is not an array",
                "400062": "The `hash` field is empty",
                "400063": "Exceeded maximum allowed",
                "400064": "The hash value is not valid",
                "400065": "The header `include_scan_details` has to be either 0 or 1",
                "400066": "The header `file_metadata` has to be either 0 or 1",
                "400067": "Hash update failed"
            },
            "Top Hash Errors": {
                "400080": "'The amount must be lower than 10, 000'",
                "400081": "Type must be one of `clean` / `infected`",
                "400082": "Period must be one of `day` / `week` / `month`",
                "400083": "'Threshold must be one of 1, 2, 3, 4, 5, 6'"
            },
            "appinfo": {
                "400100": "The fields `os_info.device_identity` are required"
            },
            "Top Detection": {
                "400120": "The header `x-exclude-empty-file-id` has to be either 0 or 1",
                "400121": "The header `x-exclude-data` has to be either 0 or 1",
                "400122": "'The header `x-threshold` must be one of 3, 4, 5, 6'",
                "400123": "'Packages should be one of m1, m4, m8, m12, m16, m20, m30'",
                "400124": "'Number of hashes must be one of 10, 100, 1, 000, 10, 000'"
            },
            "Upload Errors": {
                "400140": "The file upload has failed",
                "400141": "The header `x-force-scan` has to be either 0 or 1",
                "400142": "The header `x-sample-sharing` has to be either 0 or 1",
                "400143": "Private scanning is not enabled for the provided API key",
                "400144": "Exceeded maximum file size allowed; maximum allowed is 200MB",
                "400145": "Request body is empty; please send a binary file",
                "400146": "Provided download URL is not valid or inaccessible",
                "400147": "Rescan failed. Requested file is missing from our servers.",
                "400148": "Requested file is a private one and cannot be rescanned",
                "400149": "Could not update the rescan count",
                "400150": "The `file_ids` field array in body is required",
                "400151": "The `file_ids` field is not an array",
                "400152": "The `file_ids` field is empty",
                "400153": "Exceeded maximum allowed",
                "400154": "Exceeded maximum allowed files in archive"
            },
            "API Key Info": {
                "400160": "The API key you are trying to add already exists",
                "400161": "The API key could not be removed",
                "400162": "The API key was not updated",
                "400163": "The body is invalid",
                "400164": "No valid operation type",
                "400165": "No API key specified",
                "400166": "Please provide a valid email address",
                "400167": "Please provide a valid body",
                "400168": "'Please choose another nickname, as this one contains profanities'"
            },
            "IP Scan": {
                "400180": "Invalid format of input. Provide IPv4 or IPv6.",
                "400181": "The `ip_addresses` field in body is required",
                "400182": "The `ip_addresses` field is not an array",
                "400183": "The `ip_addresses` field is empty",
                "400184": "Exceeded maximum allowed",
                "400185": "The address is not a routable IP",
                "400186": "No response",
                "400187": "Invalid response"
            },
            "Stats": {
                "400200": "The number of days requested must be a positive integer",
                "400201": "Invalid objectId",
                "400202": "Invalid date",
                "400203": "Invalid outbreak report filter"
            },
            "Status": {
                "400210": "Parameter type must be one of `hashLookup` / `uploadFile` / `ipScan`"
            },
            "Salesforce": {
                "400250": "Salesforce connectivity error",
                "400251": "There is no record"
            },
            "Feed": {
                "400260": "You are allowed to query up to 30 days in the past",
                "400261": "'Invalid category. Please use: A, D, E, G, M, N, O, P, T, Z'"
            },
            "Authentication": {
                "401000": "Authentication has failed",
                "401001": "Authentication strategy is invalid",
                "401002": "Authentication strategy is not implemented",
                "401003": "Authorization strategy is not supported for this endpoint",
                "401004": "Authentication token has expired",
                "401005": "Authentication token is invalid",
                "401006": "Invalid API key"
            },
            "Forbidden": {
                "403000": "Access forbidden",
                "403001": "Requested resource doesn't match your API key",
                "403002": "Your IP is blocked because of abuse",
                "403003": "Insufficient Privileges"
            },
            "Not Found": {
                "404000": "Endpoint was not found",
                "404001": "Entity was not found",
                "404002": "There are no entries found",
                "404003": "The hash was not found",
                "404004": "The data_id was not found",
                "404005": "The hash information was not found",
                "404006": "There is no data for the selected date",
                "404007": "Requested file ID does not exist in our records",
                "404008": "The API key was not found"
            },
            "Payload Acceptance": {
                "406000": "Content-Type header and payload has to be JSON",
                "406001": "Payload empty"
            },
            "Request Timeout": {
                "408000": "Request timeout. It has reached the 60 seconds limit."
            },
            "Rate Limiting": {
                "429000": "API key limit exceeded; retry after the limit is reset",
                "429001": "Your request has been throttled; maximum 10 requests per minute per user",
                "429002": "Too many connections; try again later"
            },
            "Service Unavailable": {
                "503000": "External service is not reachable",
                "503001": "External service is not reachable"
            }
        }

        self.MetaLog.debug('__init__: Class initialized.')


    def scan_ip(self, target: str) -> dict:
        """ Method send IP string to Metadefender and receive response in JSON.
        Method must receive IP string to scan ('target').

        If IP was never scanned or treat not detected, return empty dictionary;
        Else return dictionary with AV name and threat name.

        Return looks like:
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

        It uses a OPSWAT Metadefender APIv4 for perform scan.
        (link: https://api.metadefender.com/v4/scan/, sends GET requests)

        Default succeed scan response code is 200;
        If code is 429, too many scan attempts made or rate limit received.
        Otherwise, see debug log for data received (debug log may content sensitive data).
        """

        self.MetaLog.debug('scan_ip: Starting IP scan.')
        self.MetaLog.debug('scan_ip: current target: {}'.format(target))

        url = "https://api.metadefender.com/v4/ip/{}".format(target)
        header = {
            'apikey': self.apikey
        }

        self.MetaLog.debug('scan_ip: Sending request.')
        response = requests.get(url, headers=header)
        self.MetaLog.debug('scan_ip: Response: {}'.format(response))
        self.MetaLog.debug('scan_ip: Received data: {}'.format(response.text))

        self.MetaLog.debug('scan_ip: checking HTTP {} code...'.format(response.status_code))
        if self.__http_code_check(response.status_code) is False:
            self.MetaLog.info('scan_ip: Bad HTTP {} code!'.format(response.status_code))
            return False
        else:
            self.MetaLog.debug('scan_ip: OK HTTP {} code.'.format(response.status_code))

        data = json.loads(response.text)

        scan_result = {}
        geo_data = {}
        geo_data['Coordinates'] = {}

        self.MetaLog.debug('scan_ip: Formating dictionaries.')
        try:
            for num in range(len(data["lookup_results"]["sources"])):
                source = data["lookup_results"]["sources"][num]["provider"]
                if data["lookup_results"]["sources"][num]["status"] == 0:
                    scan_result[source] = 'No malicious activity detected.'
                else:
                    self.MetaLog.warning('scan_ip: {} infected. Reported by {}'.format(target, source))
                    scan_result[source] = data["lookup_results"]["sources"][num]["assessment"]

            geo_data["Country"] = data["geo_info"]["country"]["name"]
            geo_data["Region"] = data["geo_info"]["continent"]["name"]
            geo_data["City"] = data["geo_info"]["city"]["name"]
            geo_data["Coordinates"]["Latitude"] = data["geo_info"]["location"]["latitude"]
            geo_data["Coordinates"]["Longitude"] = data["geo_info"]["location"]["longitude"]

        except KeyError as kerr:
            self.MetaLog.error('scan_ip: Bad data received. Probably bad request sent.')
            self.MetaLog.debug('scan_ip: KeyError arguments: {}'.format(str(kerr.args)))
            raise
        else:
            self.MetaLog.info('scan_ip: IP scan succeed.')
            return scan_result, geo_data


    def scan_file(self, target: str) -> dict:
        """ Send file\'s binary to Metadefender and receive response
        in JSON. Method must receive path to file ('target').

        It does not accept dir, only files.

        Return 2 dictionaries:
            1st. Scan results. Looks like {'Antivirus': 'File_infection_status', ...},
            2nd. Scan details. Looks like {'Total_Scanners': 42, ...}.
        Return False if bad request were sent (and response code is not 200).

        Raise FileNotFound if file not exist.
        Raise PermissionError if failed to read file\'s binary.

        It uses a OPSWAT Metadefender APIv4 for perform scan.
        (link: https://api.metadefender.com/v4/file/, sends GET requests)

        Default succeed scan HTTP response code is 200;
        If HTTP code is 429, too many scan attempts made or rate limit received.
        Otherwise, see debug log for data received (debug log may content sensitive data).
        """

        self.MetaLog.debug('scan_file: Starting file scan.')
        self.MetaLog.debug('scan_file: current target: {}'.format(target))

        target = os.path.abspath(target)
        if os.path.exists(target) is False:
            self.MetaLog.critical(target + ' not found or might not be accessed.')
            raise FileNotFoundError('File not found or might not be accessed.', target)
        elif os.path.isdir(target) is True:
            self.MetaLog.critical('scan_file: Failed reading {} binnary. Probably not file, is it a dir?'.format(target))
            raise IsADirectoryError('Object might not be send, probably object is not file.')
        else:
            self.MetaLog.debug('scan_file: file exists tests passed.')

        url = "https://api.metadefender.com/v4/file/"
        header = {
            "apikey": self.apikey,
            "content-type": "application/octet-stream"
        }

        try:
            self.MetaLog.debug('scan_file: Reading {} binnary.'.format(target))
            files = {
                os.path.basename(target): open(target, 'rb')
            }
        except PermissionError as permdenied:
            self.MetaLog.critical('scan_file: Failed reading {} binnary. Probably permissions denied.'.format(target))
            self.MetaLog.debug('scan_file: PermissionError arguments: {}'.format(str(permdenied.args)))
            raise

        self.MetaLog.debug('scan_file: Sending request.')
        response = requests.post(url, headers=header, files = files)
        self.MetaLog.debug('scan_file: Received code: {}'.format(response))
        self.MetaLog.debug('scan_file: Received data: {}'.format(response.text))

        self.MetaLog.debug('scan_file: checking HTTP {} code...'.format(response.status_code))
        if self.__http_code_check(response.status_code) is False:
            self.MetaLog.info('scan_file: Bad HTTP {} code!'.format(response.status_code))
            return False
        else:
            self.MetaLog.debug('scan_file: OK HTTP {} code.'.format(response.status_code))

        self.MetaLog.debug('scan_file: loads received JSON data.')
        data = json.loads(response.text)

        if self.__check_response_data(data, response.status_code) is False:
            self.MetaLog.error('scan_file: Bad data received. Probably bad request sent.')
            self.MetaLog.debug('scan_file: __check_response_data returned False.')
            return False
        else:
            self.MetaLog.info('scan_file: Requests sent.')
            self.MetaLog.debug('scan_file: Calling for __request_file_scan_report with argument {}'.format(str(data["data_id"])))
            return self.__request_file_scan_report(data["data_id"])

    def __request_file_scan_report(self, data_id: str, timer = 5) -> dict:
        """ Lookup for scan results.
        Send 'data_id' to Metadefender to check if scan was complete.

        'data_id' - is a string with about 36 chars, received from Metadefender.
        'timer' - time to wait after each attempt.

        Call for __parse_scan_report and return formated scan results. 
        Else return False.

        It uses a OPSWAT Metadefender APIv4 for perform scan.
        (link: https://api.metadefender.com/v4/file/, HTTP GET requests)
        """

        self.MetaLog.debug('__request_file_scan_report: Requesting scan report for {}'.format(data_id))
        url = "https://api.metadefender.com/v4/file/{}".format(data_id)
        header = {
            'apikey': self.apikey
        }

        self.MetaLog.debug('__request_file_scan_report: Sending request.')
        response = requests.get(url, headers=header)
        self.MetaLog.debug('__request_file_scan_report: Received code: {}'.format(response.status_code))
        self.MetaLog.debug('__request_file_scan_report: Received data: {}'.format(response.text))

        self.MetaLog.debug('__request_file_scan_report: checking HTTP {} code...'.format(response.status_code))
        if self.__http_code_check(response.status_code) is False:
            self.MetaLog.info('__request_file_scan_report: Bad HTTP {} code!'.format(response.status_code))
            return False
        else:
            self.MetaLog.debug('__request_file_scan_report: OK HTTP {} code.'.format(response.status_code))

        self.MetaLog.debug('__request_file_scan_report: loads received JSON data.')
        data = json.loads(response.text)

        try:
            self.MetaLog.debug('__request_file_scan_report: Check if scan progress done.')
            if data["scan_results"]["progress_percentage"] != 100:
                self.MetaLog.debug('__request_file_scan_report: Scan not done yet. Trying again.')
                time.sleep(timer)
                self.__request_file_scan_report(data_id)
        except KeyError as kerr:
            self.MetaLog.error('__request_file_scan_report: Bad data received. Probably bad request sent.')
            self.MetaLog.debug('__request_file_scan_report: KeyError arguments: {}'.format(str(kerr.args)))
            raise
        else:
            self.MetaLog.info('__request_file_scan_report: Scan seccessfully done.')
            self.MetaLog.debug('__request_file_scan_report: Calling for __parse_scan_report.')
            return self.__parse_scan_report(data)


    def scan_hash(self, target: str) -> dict:
        """ Perform SHA-256 calculation, send file hash to Metadefender
        and receive response in JSON. Method must receive path to file ('target').

        Return 2 dictionaries:
            1st. Scan results. Looks like {'Antivirus': 'File_infection_status', ...},
            2nd. Scan details. Looks like {'Total_Scanners': 42, ...}.
        Return False if check was not successfull.

        If target is not found, raise FileNotFound.

        It uses a OPSWAT Metadefender APIv4 for perform scan.
        (link: https://api.metadefender.com/v4/hash/, HTTP GET requests)
        """

        self.MetaLog.debug('scan_hash: Starting file scan.')
        if os.path.exists(target) is False:
            self.MetaLog.critical('scan_hash: {} not found or might not be accessed.'.format(target))
            raise FileNotFoundError('File not found or might not be accessed.', str(target))
        elif os.path.isdir(target) is True:
            self.MetaLog.critical('scan_hash: Failed reading {} binnary. Probably not file, is it dir?'.format(target))
            raise IsADirectoryError('Object might not be send, probably object is not file.')
        else:
            self.MetaLog.debug('scan_hash: file exists tests passed.')

        self.MetaLog.debug('scan_hash: Calculating hash for {}...'.format(target))
        hashsum = self.__get_hash(target)
        self.MetaLog.debug('scan_hash: Hash for {} is {}'.format(target, hashsum))

        url = "https://api.metadefender.com/v4/hash/{}".format(hashsum)
        header = {
            "apikey": str(self.apikey)
        }

        self.MetaLog.debug('scan_hash: Sending request.')
        response = requests.get(url, headers=header)
        self.MetaLog.debug('scan_hash: Received code: {}'.format(response))
        self.MetaLog.debug('scan_hash: Received data: {}'.format(response.text))

        self.MetaLog.debug('scan_hash: checking HTTP {} code...'.format(response.status_code))
        if self.__http_code_check(response.status_code) is False:
            self.MetaLog.info('scan_hash: Bad HTTP {} code!'.format(response.status_code))
            return False
        else:
            self.MetaLog.debug('scan_hash: OK HTTP {} code.'.format(response.status_code))

        self.MetaLog.debug('scan_hash: loads received JSON data.')
        data = json.loads(response.text)
        self.MetaLog.debug('scan_hash: received data: {}'.format(str(data)))

        if self.__check_response_data(data, response.status_code) is False:
            self.MetaLog.error('scan_hash: Bad data received. Probably bad request sent.')
            self.MetaLog.debug('scan_hash: __check_response_data returned False.')
            return False
        else:
            self.MetaLog.debug('scan_hash: Scan complete.')
            self.MetaLog.debug('scan_hash: Calling for __request_file_scan_report with argument {}'.format(data["data_id"]))
            return self.__parse_scan_report(data)

    def __get_hash(self, target: str) -> str:
        """ Calculate SHA-256.
        It reads file\'s ('target') binnary and calculate it\'s hash.

        Return file hash if calculated success.
        If file is unavailable or might not be accessed, raise PermissionError or FileNotFound error.

        SHA-256 used in Metadefender APIv4 for file identification.
        """

        self.MetaLog.debug('__get_hash: Calculating hash for {}'.format(str(target)))
        try:
            with open(target, 'rb') as file_:
                process = get_sha256()
                while True:
                    data = file_.read(8192)
                    if not data:
                        break
                    process.update(data)
        except PermissionError as permissions_denied:
            self.MetaLog.critical('__get_hash: Failed reading  {} binnary. Probably permissions denied.'.format(target))
            self.MetaLog.debug('__get_hash: PermissionError arguments: {}'.format(str(permissions_denied.args)))
            raise
        except FileNotFoundError as file_not_found_err:
            self.MetaLog.critical('__get_hash: {} not found.'.format(target))
            self.MetaLog.debug('__get_hash: FileNotFoundError arguments: {}'.format(str(file_not_found_err.args)))
            raise
        else:
            calculated_hash = str(process.hexdigest())
            self.MetaLog.debug('__get_hash: Complete hash calculating. Hash for {} is {}'.format(target, calculated_hash))
            return calculated_hash


    def __parse_scan_report(self, data: str) -> dict:
        """ Format response data and return dictionaries with scan reports.
        It format dictionary with antiviruses scan results (scan_results) and
        dictionary with general Metadefender scan information (scan_details).

        'data' - is a json dump to be formated.
        'debug' - used to save received response as json for manual read.

        Return 2 dictionaries:
            1st. 'scan_result'. Looks like {'Antivirus': 'File_infection_status', ...},
            2nd. 'scan_details'. Looks like {'Total_Scanners': 42, ...}.

        If data is not correct, return False.

        This function used by scan_hash and scan_file function to format Metadefender output.
        """

        self.MetaLog.debug('__parse_scan_report: Parsing scan results.')

        scan_result = {}
        scan_details = {}

        try:
            target = data["file_info"]["display_name"]
            for AV in data["scan_results"]["scan_details"]:
                if data["scan_results"]["scan_details"][AV]["scan_result_i"] != 0:
                    self.MetaLog.warning('__parse_scan_report: {} infected. Reported by {}.'.format(target, AV))
                    scan_result[AV] = data["scan_results"]["scan_details"][AV]["threat_found"] # May be empty
                else:
                    self.MetaLog.info('__parse_scan_report: {}: {} reported {}'.format(target, AV, self._scan_result_keys[data["scan_results"]["scan_details"][AV]["scan_result_i"]]))
                    scan_result[AV] = self._scan_result_keys[data["scan_results"]["scan_details"][AV]["scan_result_i"]]

            scan_details['TotalAV'] = data["scan_results"]["total_avs"]
            self.MetaLog.info('__parse_scan_report: {} scanned by {} engins.'.format(target, data["scan_results"]["total_avs"]))

            scan_details['TotalDetections'] = data["scan_results"]["total_detected_avs"]
            self.MetaLog.info('__parse_scan_report: {} reported by {} engins.'.format(target, data["scan_results"]["total_detected_avs"]))

            scan_details['TotalRecognized'] = data["scan_results"]["scan_all_result_a"]
            self.MetaLog.info('__parse_scan_report: {} recognized: {}'.format(target, data["scan_results"]["scan_all_result_a"]))

            scan_details['TimeSpent'] = data["scan_results"]["total_time"]
            self.MetaLog.info('__parse_scan_report: Total time spent for scan {}: {}'.format(target, data["scan_results"]["total_time"]))

        except LookupError as list_err:
            self.MetaLog.critical('__parse_scan_report: Failed to parse scan response.')
            self.MetaLog.debug('__parse_scan_report: LookupError arguments: {}'.format(str(list_err.args)))
            return False
        else:
            self.MetaLog.debug('__parse_scan_report: Complete.')
            return scan_result, scan_details


    def __check_response_data(self, data: str, http_code: int) -> bool:
        """ Check for Error signs in received data.
        Check for:
            "Not Found" value in first object (key);
            False value in "success" object (key);

        'data' - is a JSON dump, received from Metadefender.

        Return True if check done successfully.
        Return False if found sign of unsuccessful scan.
        """

        self.MetaLog.debug('__check_response_data: Starting data validation.')

        try:
            if data[0] == "Not Found":
                self.MetaLog.error('Test 1: data validation unsuccessful. Probably file was never scanned.')
                self.MetaLog.debug('__check_response_data: Test 1: {} {}'.format(str(list(data.keys())[0]), str(list(data.values())[0])))
                return False
        except KeyError:
            self.MetaLog.debug('__check_response_data: Test 1 passed.')

        try:
            if data["success"] is False:
                self.__respond_code_check(str(data["code"]["error"]))
                self.MetaLog.error('__check_response_data: Test 2: data validation unsuccessful.')
                self.MetaLog.debug('__check_response_data: Test 2: {}'.format(data["error"]["messages"][0]))
                return False
        except KeyError:
            self.MetaLog.debug('__check_response_data: Test 2 passed.')

        self.MetaLog.debug('__check_response_data: Tests passed.')
        return True

    def __respond_code_check(self, code: str) -> bool:
        """ Check received Metadefender code and HTTP code.

        Return True if received code is not in error respond list;
        Return False if received code is in error respond list;
        """

        self.MetaLog.debug('__respond_code_check: starting __respond_code_check...')
        self.MetaLog.debug('__respond_code_check: Check {} code.'.format(code))

        for category in self._metadefender_error_codes:
            for err_code in self._metadefender_error_codes[category]:

                if code == err_code:
                    self.MetaLog.debug('__respond_code_check: code in list;')
                    self.MetaLog.warning('__respond_code_check: {}: {}; {}'.format(code, category, self._metadefender_error_codes[category][err_code]))
                    return False

        self.MetaLog.debug('__respond_code_check: code is valid and might be used for scanning;')
        return True

    def __http_code_check(self, http_code: int) -> bool:
        """ Check received HTTP response code.

        Check if received HTTP response code is OK.
        For filtering codes, it uses list of Metadefender status codes returned by the REST API.
        All possible codes defined in '_http_status_codes'.

        If HTTP code is 2XX (200, 204, ...), return True;
        If HTTP code is 3XX (301, ...), return True;
        If HTTP code is 4XX (400, 401, ...), return False;
        If HTTP code is 5XX (500, 501, ...), raise ConnectionRefusedError.

        If code is not defined in '_http_status_codes', then raise ValueError.

        Logging category is defined in '_http_status_codes' in 'Logging' category, and equal to Python 'Logging levels'.
        """

        self.MetaLog.debug('__http_code_check: starting HTTP code check...')

        self.MetaLog.debug('__http_code_check: looking for {} HTTP code response description;'.format(http_code))
        if http_code in self._http_status_codes:

            # Logging first.
            self.MetaLog.debug('__http_code_check: {} HTTP code is in list;'.format(http_code))
            if self._http_status_codes[http_code]['Logging'] == 20:
                self.MetaLog.info('__http_code_check: {} HTTP code received, status: {}, description: {}'.format(http_code, self._http_status_codes[http_code]["Status"], self._http_status_codes[http_code]["Description"]))
            elif self._http_status_codes[http_code]['Logging'] == 30:
                self.MetaLog.warning('__http_code_check: {} HTTP code received, status: {}, description: {}'.format(http_code, self._http_status_codes[http_code]["Status"], self._http_status_codes[http_code]["Description"]))
            elif self._http_status_codes[http_code]['Logging'] == 40:
                self.MetaLog.error('__http_code_check: {} HTTP code received, status: {}, description: {}'.format(http_code, self._http_status_codes[http_code]["Status"], self._http_status_codes[http_code]["Description"]))
            elif self._http_status_codes[http_code]['Logging'] == 50:
                self.MetaLog.critical('__http_code_check: {} HTTP code received, status: {}, description: {}'.format(http_code, self._http_status_codes[http_code]["Status"], self._http_status_codes[http_code]["Description"]))

            if 200 <= http_code < 300:
                self.MetaLog.info('__http_code_check: OK HTTP code received.')
                return True
            elif 300 <= http_code < 400:
                self.MetaLog.info('__http_code_check: OK HTTP code received.')
                return True
            elif 400 <= http_code < 500:
                self.MetaLog.warning('__http_code_check: Client-side problem detected.')
                return False
            elif 500 <= http_code:
                self.MetaLog.error('__http_code_check: Server-side problem detected.')
                raise ConnectionRefusedError('Metadefender: __http_code_check: Server-side problem detected, please, try again later.')

        else:
            self.MetaLog.error('__http_code_check: {} HTTP code is not in list;'.format(http_code))
            raise ValueError('Metadefender: __http_code_check: Unknown HTTP response received: {} !'.format(http_code))
