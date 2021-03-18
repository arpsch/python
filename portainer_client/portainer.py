#!/usr/bin/env python3

import os
import sys
import argparse
import json
import binascii

import requests
from base64 import b64encode
from urllib.error import HTTPError

JWT = ''

# URL of portainer hosted instancce
server = "https://localhost"

PORTAINER_LOGIN="/api/auth"
PORTAINER_EPS = "/api/endpoints"

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--server', help="portainer server url/ip", required=True)
parser.add_argument('-u', '--username', help="administrator username", required=True)
parser.add_argument('-p', '--password', help="administrator password",required=True)
parser.add_argument('-o', '--port',help="port on docker host exposed for portainer agent", required=True)
parser.add_argument('-e', '--endpoint', help="endpoint name to be created i.e. url of docker host", required=True)

def get_url(service):
    '''
    returns the url for corresponding operation
    '''
    global server
    if service == 'login':
        return server + PORTAINER_LOGIN
    elif service == 'endpoints':
        return server + PORTAINER_EPS


def login(username, password):
    '''
    Accepts the username and password on successful login
    set JWT to globa variable 'JWT'
    '''
    headers = {"accept": "application/json",
               "Content-Type": "application/json"}
    payload = json.dumps({
                "Username": username,
                "Password": password,
        })

    try:
        global JWT
        response = requests.post(get_url('login'), headers=headers, data=payload)
    except HTTPError  as http_err:
        print('HTTP error occured: {}'.format(http_err))
        return http_err
    except Exception as err:
        print('Other error occured: {}'.format(err))
        return err
    else:
        if response.status_code == 200:
            print("logged in user {}".format(username))
            JWT = response.json()['jwt']
        else:
            return response.status_code
    return 0



def encode_multipart_formdata(fields):
    '''
    encodes the input dictionary to comply
    with multipart/form-data header.
    it produces bounday param as well
    returns:
       body - can be data para of request
       content_type - can be set as content-type header
    '''
    boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

    body = (
        "".join("--%s\r\n"
                "Content-Disposition: form-data; name=\"%s\"\r\n"
                "\r\n"
                "%s\r\n" % (boundary, field, value)
                for field, value in fields.items()) +
        "--%s--\r\n" % boundary
    )

    content_type = "multipart/form-data; boundary=%s" % boundary

    return body, content_type

''' ep_type = 2 - agent environment'''
'''
curl -vvv -X POST "https://portainer.francecentral.azurecontainer.io/api/endpoints"
-H "accept: application/json"
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOjEsImV4cCI6MTYxNjA4ODc1Nn0.BRMEIEu8WQUUgHCz7Cb75p5XVg3VTtMiVOWhVKk2f2g"
-H "Content-Type: multipart/form-data"
-F "Name=endpoint-test"
-F "EndpointCreationType=2"
-F "URL=https://trial.edgeway.io:9001"
-F "TLS=true"
-F "TLSSkipVerify=true"
-F "TLSSkipClientVerify=true"
'''
def create_portainer_endpoint(name, ep_type, ep_url, ep_public_url):
    '''
    creates an endopint in the hosted portainer.
    make sure the agent is installed in the machine represeting ep_url
    if hosting in cloud, open port specified.
    '''
    global JWT

    files, content_type = encode_multipart_formdata({
        "Name": name,
        "EndpointCreationType": ep_type,
        "URL": ep_url,
        "PublicURL": ep_public_url,
        "TLS": "true",
        "TLSSkipVerify":"true",
        "TLSSkipClientVerify":"true"
    })

    headers = { "accept": "application/json",
                "Authorization": "Bearer "+ JWT,
                "Content-Type": content_type}

    try:
        response = requests.post(get_url('endpoints'), headers=headers, data=files)
    except HTTPError  as http_err:
        print('HTTP error occured: {}'.format(http_err))
        return http_err
    except Exception as err:
        print('Other error occured: {}'.format(err))
        return err
    else:
        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code)
            print(response.text)
            return response.status_code
    return 0

def search_portainer_endpoint(name):
    '''
    searches the portainer set-up for the matching string
    it shall return check name, url
    '''
    headers = { "Authorization": "Bearer "+ JWT,
                'Content-Type': 'application/json' }

    try:
        rsp = requests.get(get_url('endpoints')+"?"+name, headers=headers)
    except HTTPError  as http_err:
        print('HTTP error occured: {}'.format(http_err))
    except Exception as err:
        print('Other error occured: {}'.format(err))
    else:
        if rsp.status_code == 200:
            return rsp.json()
        else:
            print("failed to get end point config")
            print(rsp.text)
    return ""

def delete_portainer_endpoint(name):
    '''
    deletes the endpoint entry
    '''
    headers = { "Authorization": "Bearer "+ JWT }
    rsp = search_portainer_endpoint(name)

    if len(rsp) == 0:
        print("portainer endpoint not found")
    for v in rsp:
        if (v['Name'] == name):
            print("Deleting endpoint: " + str(v['Id']), v['Name'], v['URL'])
            try:
                rsp = requests.delete(get_url('endpoints')+"/"+str(v['Id']), headers=headers)
            except HTTPError  as http_err:
                print('HTTP error occured: {}'.format(http_err))
            except Exception as err:
                print('Other error occured: {}'.format(err))
            else:
                if rsp.status_code == 204:
                    print("Success: deleted endpoint")
                else:
                    print("failed to delete endpoint")
                    print(rsp.text)
                break

def main():
    global server
    args = parser.parse_args()

    server = args.server
    print("portainer server URL: " + args.server)
    print("portainer endpoint name: " + args.endpoint)

    err = login(args.username, args.password)
    if  err:
        print("failed to login, try agian!", err)
        return

    ep_name = args.endpoint
    ep_type = 2  # 2 for Agent is running on docker host.
    ep_url = "https://"+args.endpoint+":" + args.port
    ep_public_url = "https://"+ args.endpoint

    #delete_portainer_endpoint(ep_name)

    rsp = search_portainer_endpoint(ep_name)
    for v in rsp:
        if (v['Name'] == ep_name):
            print(" portainer endpoint exists")
            exit(0)
    rsp = create_portainer_endpoint(ep_name, ep_type, ep_url, ep_public_url)
    print("*" * 100)
    print(rsp['Name'] + " portainer endpoint is created")
    print("*" * 100)


if __name__ == "__main__":
    main()
