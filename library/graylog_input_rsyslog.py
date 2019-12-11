#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Matthieu SIMON
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: graylog_input_rsyslog
short_description: Manage Graylog input type Syslog
description:
    - The Graylog inputs module allows configuration of input type Syslog on nodes.
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
      - Action to take against system/input API.
      - Warning : when update, all settings with default value set in this Ansible module (like bind_address, port ...) will replace existing values
        You must explicitly set these values if they differ from those by default
    required: true
    default: create
    choices: [ create, update ]
    type: str
  input_type:
    description:
      - Input type
    required: false
    default: UDP
    choices: [ 'UDP', 'TCP' ]
    type: str
  title:
    description:
      - Entitled of the input
    required: true
    type: str
  input_id:
    description:
      - ID of input to update
    required: false
    type: str
  global_input:
    description:
      - Should this input start on all nodes
    required: false
    default: true
    type: bool
  node:
    description:
      - Node name if input is not global
    required: false
    type: str
  bind_address:
    description:
      - Address to listen on
    required: false
    default: "0.0.0.0"
    type: str
  port:
    description:
      - Port to listen on
    required: true
    default: 514  
    type: int
  allow_override_date:
    description:
      - Allow to override with current date if date could not be parsed
    required: false
    default: false
    type: bool
  expand_structured_data:
    description:
      - Expand structured data elements by prefixing attributes with their SD-ID
    required: false
    default: false
    type: bool
  force_rdns:
    description:
      - Force rDNS resolution of hostname. Use if hostname cannot be parsed. (Be careful if you are sending DNS logs into this input because it can cause a feedback loop.) 
    required: false
    default: false
    type: bool
  number_worker_threads:
    description:
      - Number of worker threads processing network connections for this input.
    required: false
    default: 2
    type: int
  override_source:
    description:
      - The source is a hostname derived from the received packet by default. Set this if you want to override it with a custom string.
    required: false
    type: str
  recv_buffer_size:
    description:
      - The size in bytes of the recvBufferSize for network connections to this input.
    required: false
    default: 1048576
    type: int
  store_full_message:
    description:
      - Store the full original syslog message as full_message
    required: false
    default: false
    type: bool
  tcp_keepalive:
    description:
      - Enable TCP keepalive packets (TCP only)
    required: false
    default: false
    type: bool
  tls_enable:
    description:
      - Accept TLS connections  (TCP only)
    required: false
    default: false
    type: bool
  tls_cert_file:
    description:
      - Path to the TLS certificate file (TCP only)
    required: false
    type: str
  tls_key_file:
    description:
      - Path to the TLS private key file (TCP only)
    required: false
    type: str
  tls_key_password:
    description:
      - The password for the encrypted key file. (TCP only)
    required: false
    type: str
  tls_client_auth:
    description:
      - Whether clients need to authenticate themselves in a TLS connection (TCP only)
    required: false
    default: disabled
    choices: [ 'disabled', 'optional', 'required' ]
  tls_client_auth_cert_file:
    description:
      - TLS Client Auth Trusted Certs (File or Directory)  (TCP only)
    required: false
    type: str
  use_null_delimiter:
    description:
      - Use null byte as frame delimiter ? Otherwise newline delimiter is used. (TCP only)
    required: false
    default: false
    type: bool
'''

EXAMPLES = '''
  - name: Create Rsyslog TCP input
    graylog_input_rsyslog:
      endpoint: "{{ graylog_endpoint }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      allow_http: "true"
      validate_certs: "false"
      action: "create"
      input_type: "TCP"
      title: "Rsyslog TCP"
      global_input: "true"
      allow_override_date: "true"
      bind_address: "0.0.0.0"
      expand_structured_data: "false"
      force_rdns: "false"
      number_worker_threads: "2"
      port: "514"
      recv_buffer_size: "1048576"
      store_full_message: "true"


  - name: Update existing input
    graylog_input_rsyslog:
      endpoint: "{{ graylog_endpoint }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      allow_http: "true"
      validate_certs: "false"
      action: "update"
      input_type: "TCP"
      title: "Rsyslog TCP"
      global_input: "true"
      allow_override_date: "true"
      expand_structured_data: "false"
      force_rdns: "true"
      port: "1514"
      store_full_message: "true"
      input_id: "1df0f1234abcd0000d0adf20"
'''

# import module snippets
import json
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text


def update(module, base_url, headers):

    configuration = {}
    for key in [ 'bind_address', 'port', 'allow_override_date', 'expand_structured_data', 'force_rdns', \
                 'number_worker_threads', 'override_source', 'recv_buffer_size', 'store_full_message', \
                 'tcp_keepalive', 'tls_enable', 'tls_cert_file', 'tls_key_file', 'tls_key_password', \
                 'tls_client_auth', 'tls_client_auth_cert_file', 'use_null_delimiter' ]:
        if module.params[key] is not None:
            configuration[key] = module.params[key]

    payload = {}

    payload['type'] = module.params['input_type']
    payload['title'] = module.params['title']
    payload['global'] = module.params['global_input']
    payload['node'] = module.params['node']
    payload['configuration'] = configuration

    if module.params['action'] == "create":
      httpMethod = "POST"
    else:
      httpMethod = "PUT"
      base_url = base_url + "/" + module.params['input_id']

    response, info = fetch_url(module=module, url=base_url, headers=json.loads(headers), method=httpMethod, data=module.jsonify(payload))

    if info['status'] != 201:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, base_url


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
            action=dict(type='str', required=False, default='create', 
                        choices=[ 'create', 'update' ]),
            input_type=dict(type='str', required=False, default='UDP', 
                        choices=[ 'UDP', 'TCP' ]),
            title=dict(type='str', required=True),
            input_id=dict(type='str', required=False),
            global_input=dict(type='bool', required=False, default=True),
            node=dict(type='str', required=False),
            bind_address=dict(type='str', required=False, default='0.0.0.0'),
            port=dict(type='int', required=False, default=514),
            allow_override_date=dict(type='bool', required=False, default=False),
            expand_structured_data=dict(type='bool', required=False, default=False),
            force_rdns=dict(type='bool', required=False, default=False),
            number_worker_threads=dict(type='int', required=False, default=2),
            override_source=dict(type='str', required=False),
            recv_buffer_size=dict(type='int', required=False, default=1048576),
            store_full_message=dict(type='bool', required=False, default=False),
            tcp_keepalive=dict(type='bool', required=False, default=False),
            tls_enable=dict(type='bool', required=False, default=False),
            tls_cert_file=dict(type='str', required=False),
            tls_key_file=dict(type='str', required=False),
            tls_key_password=dict(type='str', required=False),
            tls_client_auth=dict(type='str', required=False, default='disabled', 
                        choices=[ 'disabled', 'optional', 'required' ]),
            tls_client_auth_cert_file=dict(type='str', required=False),
            use_null_delimiter=dict(type='bool', required=False, default=False)
        )
    )

    endpoint = module.params['endpoint']
    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    allow_http = module.params['allow_http']


    if allow_http == True:
      endpoint = "http://" + endpoint
    else:
      endpoint = "https://" + endpoint

    # Build full name of input type
    if module.params['input_type'] == "UDP":
        module.params['input_type'] = "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
    else:
        module.params['input_type'] = "org.graylog2.inputs.syslog.tcp.SyslogTCPInput"

    base_url = endpoint + "/api/system/inputs"

    api_token = get_token(module, endpoint, graylog_user, graylog_password, allow_http)
    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json", \
                "Authorization": "Basic ' + api_token.decode() + '" }'

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
