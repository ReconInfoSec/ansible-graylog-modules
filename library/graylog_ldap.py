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
    default: get
    choices: [ get, update, delete, test ]
    type: str
  enabled:
    description:
      - Enable / disable LDAP authentication
    required: false
    type: bool
  active_directory:
    description:
      - Define LDAP flavour as Active Directory
    required: false
    default: false
    type: bool
  ldap_uri:
    desctiption:
      - LDAP URI (ex ldap://myldapserver.mydomain.com:389)
    required: false
    type: str
  use_start_tls
    description:
      - Enable start TLS
    required: false
    default: false
    type: bool
  trust_all_certificates:
    description:
      - Allow LDAP self-signed certificates
    required: false
    default: false
    type: bool
  system_password_set:
    description:
      - Enable binding authentication
    required: false
    default: false
    type: str    
  system_username:
    description:
      - The username for LDAP binding, e.g. ldapbind@some.domain.
    required: false
    type: str
  system_password:
    description:
      - Bind username password
    required: false
    type: str
  search_base:  
    description:
      - The base tree to limit the user search query to, e.g. cn=users,dc=example,dc=com
    required: false
    type: str
  search_pattern:
    description:
      - User search filter. For example (&(objectClass=user)(sAMAccountName={0}))
    required: false
    type: str  
  display_name_attribute
    description:
      - Attribute to use for the full name of the user in Graylog
    required: false
    type: str    
  group_search_base:
    description:
      - The base tree to limit the LDAP group search query to
    required: false
    type: str   
  group_search_pattern:
    description:
      - The search pattern used to find groups in LDAP for mapping to Graylog roles
    required: false
    type: str   
  group_id_attribute:
    description:
      - Attribute to use for the full name of the group, usually cn
    required: false
    type: str
  default_group:
    description:
      - Default role assigned to LDAP group
    required: false
    default: Reader
    type: str
  group_mapping:
    description:
      - Additional roles assigned to LDAP group
    required: false
    type: list
'''

EXAMPLES = '''
# Setup Active Directory authentication without SSL and set "Reader" as default role
- graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    enabled: "true"
    action: "update"
    active_directory: "true"
    ldap_uri: "ldap://domaincontroller.mydomain.com:389"
    system_password_set: "true"
    system_username: "ldapbind@mydomain.com"
    system_password: "bindPassw0rd"
    search_base: "cn=users,dc=mydomain,dc=com"
    search_pattern: "(&(objectClass=user)(sAMAccountName={0}))"    
    display_name_attribute: "displayName"
    group_search_base: "cn=groups,dc=mydomain,dc=com"
    group_search_pattern: "(&(objectClass=group)(cn=graylog*))"
    group_id_attribute: "cn"

# Remove current LDAP authentication configuration
- graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "delete"

# Get current LDAP authentication configuration
- graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"   
    action: "get"
  register: currentConfiguration

- name: Print
  debug:
    msg: "{{ currentConfiguration }}"

# Test LDAP bind
- graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "test"
    active_directory: "true"
    ldap_uri: "ldap://domaincontroller.mydomain.com:389"
    system_password_set: "true"
    system_username: "ldapbind@mydomain.com"
    system_password: "bindPassw0rd"
'''

# import module snippets
import json
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text


def get(module, base_url, headers):

    url = base_url + "/settings"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def delete(module, base_url, headers):

    url = base_url + "/settings"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='DELETE')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def test(module, base_url, headers):

    url = base_url + "/test"

    payload = {}

    for key in [ 'system_username', 'system_password', 'ldap_uri', 'use_start_tls', 'trust_all_certificates', \
                 'active_directory', 'search_base', 'search_pattern', 'group_search_base', 'group_id_attribute', \
                 'group_search_pattern' ]:
        if module.params[key] is not None:
            payload[key] = module.params[key]

    payload['test_connect_only'] = "true"

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST', data=module.jsonify(payload))

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    jsonContent = json.loads(content)

    if jsonContent['connected'] == False:
      module.fail_json(msg="Fail: LDAP bind fail !")

    return info['status'], info['msg'], content, url


def update(module, base_url, headers):

    url = base_url + "/settings"

    payload = {}

    for key in ['enabled', 'active_directory', 'ldap_uri', 'use_start_tls', 'trust_all_certificates', \
                'system_password_set', 'system_username', 'system_password', 'search_base', 'search_pattern', \
                'display_name_attribute', 'group_search_base', 'group_search_pattern', 'group_id_attribute', \
                'default_group', 'group_mapping', 'enabled', 'active_directory' ]:
        if module.params[key] is not None:
            payload[key] = module.params[key]
    
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
            action=dict(type='str', required=False, default='get', 
                        choices=['get', 'update', 'delete', 'test']),
            allow_http=dict(type='bool', required=False, default=False),
            validate_certs=dict(type='bool', required=False, default=True),
            enabled=dict(type='bool', required=False, default=False),
            active_directory=dict(type='bool', required=False, default=False),
            ldap_uri=dict(type='str', required=False),
            use_start_tls=dict(type='bool', required=False, default=False),
            trust_all_certificates=dict(type='bool', required=False, default=False),
            system_password_set=dict(type='bool', required=False, default=False),
            system_username=dict(type='str', required=False),
            system_password=dict(type='str', required=False, no_log=True),
            search_base=dict(type='str', required=False),
            search_pattern=dict(type='str', required=False),
            display_name_attribute=dict(type='str', required=False),
            group_search_base=dict(type='str', required=False),
            group_search_pattern=dict(type='str', required=False),
            group_id_attribute=dict(type='str', required=False),
            default_group=dict(type='str', required=False, default='Reader'),
            group_mapping=dict(type='list', required=False)
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

    if action == "get":
        status, message, content, url = get(module, base_url, headers)                
    elif action == "update":
        status, message, content, url = update(module, base_url, headers)
    elif action == "delete":
        status, message, content, url = delete(module, base_url, headers)
    elif action == "test":
        status, message, content, url = test(module, base_url, headers)
       
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
