############################################################################################################################
#                                                IMPORT REQUIRED LIBRARIES                                                 #
############################################################################################################################
import urllib.parse
import requests
import hashlib
import secrets
import base64
import hmac
import time

############################################################################################################################
#                                            ROUTINE FOR MAKING OAUTH REQUESTS                                             #
############################################################################################################################
def get(url, parameters, consumer_key, consumer_secret, token=None, token_secret=None):
    print("OAuth GET")

    #Default parameters
    method = "GET"

    #Generate signing key
    signing_key = urllib.parse.quote(consumer_secret,safe='')+"&"
    if token_secret is not None:
        signing_key += urllib.parse.quote(token_secret,safe='')

    #Set required parameters
    parameters["oauth_consumer_key"]     = consumer_key
    parameters["oauth_version"]          = "1.0"
    parameters["oauth_signature_method"] = "HMAC-SHA1"
    parameters["oauth_timestamp"]        = str(int(time.time()))
    parameters["oauth_nonce"]            = secrets.token_urlsafe()

    if token is not None:
        parameters["oauth_token"] = token

    #Generate parameter string
    parameter_string = ""
    encoded = {}
    for key in parameters.keys():
        encoded[urllib.parse.quote(str(key),safe='')] = urllib.parse.quote(str(parameters[key]),safe='')
    encoded_keys = sorted(encoded.keys())
    for i in range(0, len(encoded_keys)):
        parameter_string += encoded_keys[i] + "=" + encoded[encoded_keys[i]]
        if i < len(encoded_keys) - 1:
            parameter_string += "&"

    #Generate base string
    base_string = method.upper()+"&"+urllib.parse.quote(url,safe='')+"&"+urllib.parse.quote(parameter_string)

    #Generate OAuth signature
    oauth_signature = urllib.parse.quote(str(base64.urlsafe_b64encode(hmac.new(bytes(signing_key, "UTF-8"), bytes(base_string, "UTF-8"), hashlib.sha1).digest()), "UTF-8"), safe='')

    #Add signature to parameters
    parameters["oauth_signature"] = oauth_signature

    print(f"Signature for request: {oauth_signature}")
    print(f"Request URL: {url}")
    print(f"Request Parameters: {parameters}")

    #Make request
    return requests.get(url, parameters)
