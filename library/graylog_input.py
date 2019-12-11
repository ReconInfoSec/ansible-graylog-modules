#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Matthieu SIMON
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: graylog_input
short_description: Manage Graylog inputs
description:
    - The Graylog inputs module allows configuration of inputs nodes.
version_added: "2.9"
author: "Matthieu SIMON"
options:
  endpoint:
    description:
      - Graylog endoint. (i.e. graylog.mydomain.com).
    required: false
    type: str
  graylog_user:
    description:
      - Graylog privileged user username.
    required: false
    type: str
  graylog_password:
    description:
      - Graylog privileged user password.
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
    choices: [ list, delete ]
    type: str
  input_id:
    description:
      - ID of input to remove
    required: false
    type: str
'''

EXAMPLES = '''
    - name: Display all inputs
      graylog_input:
        endpoint: "{{ graylog_endpoint }}"
        graylog_user: "{{ graylog_user }}"
        graylog_password: "{{ graylog_password }}"
        allow_http: "true"
        validate_certs: "false"
        action: "list"

    - name: Remove input with ID 1df0f1234abcd0000d0adf20
      graylog_input:
        endpoint: "{{ graylog_endpoint }}"
        graylog_user: "{{ graylog_user }}"
        graylog_password: "{{ graylog_password }}"
        allow_http: "true"
        validate_certs: "false"
        action: "delete"        
        input_id: "1df0f1234abcd0000d0adf20"
'''

# import module snippets
import json
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text

def delete(module, base_url, headers):

    url = base_url + "/" + module.params['input_id']

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='DELETE')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url

def list(module, base_url, headers):

    url = base_url

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
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
            validate_certs=dict(type='bool', required=False, default=True),
            allow_http=dict(type='bool', required=False, default=False),
            action=dict(type='str', required=False, default='list', 
                        choices=[ 'list' , 'delete' ]),
            input_id=dict(type='str', required=False ),
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

    base_url = endpoint + "/api/system/inputs"

    api_token = get_token(module, endpoint, graylog_user, graylog_password, allow_http)
    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
                "Authorization": "Basic ' + api_token.decode() + '" }'

    if action == "list":
        status, message, content, url = list(module, base_url, headers)                
    elif action == "delete":
        status, message, content, url = delete(module, base_url, headers)
       
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
