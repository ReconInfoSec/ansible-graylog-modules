#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Matthieu SIMON
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: graylog_inputs
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
    choices: [ create, update, delete, list ]
    type: str
  input_type:
    description:
      - Input type (not all are implemented at this time)
    required: false
    default: SyslogUDPInput
    choices: [ 'SyslogUDPInput', 'SyslogTCPInput', 'GELFUDPInput', 'GELFTCPInput', 'GELFHttpInput' ]
    type: str
  title:
    description:
      - Entitled of the input
      - Required with actions create, update and delete
    required: false
    type: str
  global_input:
    description:
      - Input is present on all Graylog nodes
    required: false
    type: bool
  node:
    description:
      - Node name if input is not global
    required: false
    type: str
  bind_address:
    description:
      - Address to listen on
      - Required with actions create and update
    required: false
    default: "0.0.0.0"
    type: str
  port:
    description:
      - Port to listen on
      - Required with actions create and update
    required: false  
    type: int
  allow_override_date:
    description:
      - Allow to override with current date if date could not be parsed
      - Required with actions create and update
      - Required for SyslogUDPInput and SyslogTCPInput
    required: false
    default: false
    type: bool
  expand_structured_data:
    description:
      - Expand structured data elements by prefixing attributes with their SD-ID
      - Required with actions create and update
      - Required for SyslogUDPInput and SyslogTCPInput
    required: false
    default: false
    type: bool
  force_rdns:
    description:
      - Force rDNS resolution of hostname. Use if hostname cannot be parsed. (Be careful if you are sending DNS logs into this input because it can cause a feedback loop.) 
      - Required with actions create and update
      - Required for SyslogUDPInput and SyslogTCPInput
    required: false
    default: false
    type: bool
  number_worker_threads:
    description:
      - Number of worker threads processing network connections for this input.
      - Required with actions create and update
    required: false
    default: 2
    type: int
  override_source:
    description:
      - The source is a hostname derived from the received packet by default. Set this if you want to override it with a custom string.
      - Required with actions create and update
    required: false
    type: str

'''

EXAMPLES = '''

'''

# import module snippets
import json
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text

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
            validate_certs=dict(type='bool', required=False, default=True),
            allow_http=dict(type='bool', required=False, default=False),
            action=dict(type='str', required=False, default='list', 
                        choices=[ 'list' ,'create', 'update', 'delete' ]),
            input_type=dict(type='str', required=False, default='list', 
                        choices=[ 'SyslogUDPInput', 'SyslogTCPInput', 'GELFUDPInput', 'GELFTCPInput', 'GELFHttpInput' ],
            title=dict(type='str', required=False ),
            global_input=dict(type='bool', required=False, default=True),
            node=dict(type='str', required=False),
            bind_address=dict(type='str', required=False, default='0.0.0.0'),
            port=dict(type='int', required=False),
            allow_override_date=dict(type='bool', required=False, default=False),
            expand_structured_data=dict(type='bool', required=False, default=False),
            force_rdns=dict(type='bool', required=False, default=False),
            number_worker_threads=dict(type='int', required=False, default=2),
            override_source=dict(type='str', required=False),

        )
    )

    endpoint = module.params['endpoint']
    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    action = module.params['action']
    allow_http = module.params['allow_http']
    input_type = module.params['input_type']

    if allow_http == True:
      endpoint = "http://" + endpoint
    else:
      endpoint = "https://" + endpoint

    # Build full name of input type
    if input_type == "SyslogUDPInput":
        input_type = "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
    elif input_type == "SyslogTCPInput":
        input_type = "org.graylog2.inputs.syslog.tcp.SyslogTCPInput"
    elif input_type == "GELFTCPInput":
        input_type = "org.graylog2.inputs.gelf.tcp.GELFTCPInput"
    elif input_type == "GELFUDPInput":
        input_type = "org.graylog2.inputs.gelf.udp.GELFUDPInput"
    elif input_type == "GELFHttpInput":
        input_type = "org.graylog2.inputs.gelf.http.GELFHttpInput"

    base_url = endpoint + "/api/system/inputs"

    api_token = get_token(module, endpoint, graylog_user, graylog_password, allow_http)
    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
                "Authorization": "Basic ' + api_token.decode() + '" }'

    if action == "list":
        status, message, content, url = list(module, base_url, headers)                
    elif action == "create":
        status, message, content, url = create(module, base_url, headers)
    elif action == "update":
        status, message, content, url = update(module, base_url, headers)
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
