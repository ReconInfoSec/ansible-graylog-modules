#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Matthieu SIMON
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: graylog_ldap
short_description: Communicate with the Graylog API to configure LDAP authentication
description:
    - The Graylog ldap module allows configuration LDAP authentication parameters.
version_added: "2.9"
author: "Matthieu SIMON"
options:
  endpoint:
    description:
      - Graylog endpoint. (i.e. graylog.mydomain.com:9000).
    required: false
    type: str
  graylog_user:
    description:
      - Graylog privileged user username, used to auth with Graylog API.
    required: false
    type: str
  graylog_password:
    description:
      - Graylog privileged user password, used to auth with Graylog API.
    required: false
    type: str
  allow_http:
    description:
      - Allow non HTTPS connexion
    required: false
    default: false
    type: bool
  validate_certs:
    description:
      - Allow untrusted certificate
    required: false
    default: false
    type: bool      
  action:
    description:
      - Action to take against LDAP API.
    required: true
    default: list
    choices: [ list, list_mapping, update ]
    type: str
  group:
    description:
      - LDAP group whose role is to update
    required: false
    type: str
  role:
    description:
      - Graylog role to assign to the LDAP group
    require: false
    type: str
'''

EXAMPLES = '''
# Get all LDAP groups
- graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "list"

# Get the LDAP group to Graylog role mapping
- graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "list_mapping"

# Update the LDAP group to Graylog role mapping
- graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"   
    action: "update"
    group: "{{ item.group }}"
    role: "{{ item.role }}"
  with_items:
    - { group : "ldap-group-admins", role : "Admin" }
    - { group : "ldap-group-read", role : "Reader" }

# Remove Graylog role mapping
- graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"   
    action: "update"
    group: "ldap-group-foobar"
    role: "None"
'''

# import module snippets
import json
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text

def list(module, base_url, headers):

    url = base_url + "/groups"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url

def list_mapping(module, base_url, headers):

    url = base_url + "/settings/groups"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def update(module, base_url, headers):

    url = base_url + "/settings/groups"
    
    # Get current mapping
    (currentMapping) = list_mapping(module, base_url, headers)    
    payload = json.loads(currentMapping[2])
    
    # Update value  
    group = module.params['group']
    payload[group] = module.params['role']
    
    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='PUT', data=module.jsonify(payload))

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url

def get_token(module, endpoint, username, password, allow_http):

    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json" }'

    url = endpoint + "/api/system/sessions"

    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['host'] = endpoint

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST', data=module.jsonify(payload))

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        session = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    session_string = session['session_id'] + ":session"
    session_bytes = session_string.encode('utf-8')
    session_token = base64.b64encode(session_bytes)

    return session_token

def main():
    module = AnsibleModule(
        argument_spec=dict(
            endpoint=dict(type='str'),
            graylog_user=dict(type='str'),
            graylog_password=dict(type='str', no_log=True),
            action=dict(type='str', required=False, default='list', 
                        choices=[ 'list', 'list_mapping', 'update' ]),
            allow_http=dict(type='bool', required=False, default=False),
            validate_certs=dict(type='bool', required=False, default=True),
            group=dict(type='str'),
            role=dict(type='str')
        )
    )

    endpoint = module.params['endpoint']
    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    action = module.params['action']
    allow_http = module.params['allow_http']

    if allow_http == True:
      endpoint = "http://" + endpoint
    else:
      endpoint = "https://" + endpoint

    base_url = endpoint + "/api/system/ldap"

    api_token = get_token(module, endpoint, graylog_user, graylog_password, allow_http)
    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
                "Authorization": "Basic ' + api_token.decode() + '" }'

    if action == "list":
        status, message, content, url = list(module, base_url, headers)                
    elif action == "list_mapping":
        status, message, content, url = list_mapping(module, base_url, headers)
    elif action == "update":
        status, message, content, url = update(module, base_url, headers)
       
    uresp = {}
    content = to_text(content, encoding='UTF-8')

    try:
        js = json.loads(content)
    except ValueError:
        js = ""

    uresp['json'] = js
    uresp['status'] = status
    uresp['msg'] = message
    uresp['url'] = url

    module.exit_json(**uresp)


if __name__ == '__main__':
    main()
