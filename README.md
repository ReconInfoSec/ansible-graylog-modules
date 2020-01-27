# ansible-graylog-modules
Ansible modules for the [Graylog2/graylog2-server](https://github.com/graylog2/graylog2-server) API

A full example playbook can be found in `main.yml`.

### In Progress

* Indices
* Inputs

### Modules

The following modules are available with the corresponding actions:

* graylog_users
  * create
  * update
  * delete
  * list
* graylog_roles
  * create
  * update
  * delete
  * list
* graylog_streams
  * create
  * create_rule
  * update
  * update_rule
  * delete
  * delete_rule
  * list
  * query_streams - query by stream name (ie: to get stream ID)
* graylog_pipelines
  * create
  * create_rule
  * create_connection
  * update
  * update_rule
  * update_connection
  * parse_rule
  * delete
  * delete_rule
  * list
  * query_pipelines - query by pipeline name (ie: to get pipeline ID)
  * query_rules - query by rule name (ie: to get rule ID)
* graylog_index_sets
  * create
  * update
  * delete
  * list
  * query_index_sets - query by index set name (ie: to get index set ID)
* graylog_collector_configurations
  * list_configurations
  * query_collector_configurations
  * update_snippet
* graylog_ldap
  * get
  * update
  * delete
  * test
* graylog_input
  * list
  * delete
* graylog_input_rsyslog
  * create
  * update
* graylog_input_gelf
  * create
  * update


### Examples

#### Users

```
- name: Create Graylog user
  graylog_users:
    action: create
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    username: "{{ username }}"
    full_name: "Ansible User"
    password: "{{ password }}"
    email: "test-email@aol.com"
    roles:
      - "ansible_role"

- name: Get Graylog users
  graylog_users:
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
  register: graylog_users

- name: List users
  debug:
    msg: "{{ graylog_users.json }}"
```

#### Roles

```
- name: Create Graylog role
  graylog_roles:
    action: create
    endpoint: "{{ endpoint }}"
    graylog_user: "admin"
    graylog_password: "{{ graylog_password }}"
    name: "ansible_role"
    description: "Ansible test role"
    permissions:
      - "dashboards:read"
    read_only: "true"

- name: Get Graylog roles
  graylog_roles:
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
  register: graylog_roles

- name: List roles
  debug:
    msg: "{{ graylog_roles.json }}"    
```

#### Streams and Stream Rules

```
- name: Create stream
  graylog_streams:
    action: create
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    title: "test_stream"
    description: "Windows and IIS logs"
    matching_type: "AND"
    remove_matches_from_default_stream: False
    rules:
      - {"field":"message","type":1,"value":"test_stream rule","inverted": false,"description":"test_stream rule"}

- name: Get Graylog streams
  graylog_streams:
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
  register: graylog_streams

- name: Get stream from stream name query
  graylog_streams:
    action: query_streams
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    stream_name: "test_stream"
  register: stream

- name:  List single stream by ID
  graylog_streams:
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    stream_id: "{{ stream.json.id }}"

- name: Create stream rule
  graylog_streams:
    action: create_rule
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    stream_id: "{{ stream.json.id }}"
    description: "Windows Security Logs"
    field: "winlogbeat_log_name"
    type: "1"
    value: "Security"
    inverted: False       
```

#### Pipelines, Pipeline Rules, Stream connections

```
- name: Create pipeline rule
  graylog_pipelines:
    action: create_rule
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    title: "test_rule"
    description: "test"
    source: |
      rule "test_rule_domain_threat_intel"
      when
         has_field("dns_query")
      then
         let dns_query_intel = threat_intel_lookup_domain(to_string($message.dns_query), "dns_query");
         set_fields(dns_query_intel);
      end

- name: Create pipeline
  graylog_pipelines:
    action: create
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    title: "test_pipeline"
    source: |
      pipeline "test_pipeline"
      stage 0 match either
      end
    description: "test_pipeline description"

- name: Get pipeline from pipeline name
  graylog_pipelines:
    action: query_pipelines
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    pipeline_name: "test_pipeline"
  register: pipeline

- name: Update pipeline with new rule
  graylog_pipelines:
    action: update
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    pipeline_id: "{{ pipeline.json.id }}"
    description: "test description update"
    source: |
      pipeline "test_pipeline"
      stage 0 match either
      rule "test_rule_domain_threat_intel"
      end

- name: Create Stream connection to processing pipeline
  graylog_pipelines:
    action: create_connection
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    pipeline_id: "{{ pipeline.json.id }}"
    stream_ids:
      - "{{ stream.json.id }}"
```

#### Index Sets and attach Streams

```
- name: Create index set
  graylog_index_sets:
    action: create
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    title: "test_index_set"
    index_prefix: "test_index_"
    description: "test index set"

- name: Get index set by name
  graylog_index_sets:
    action: query_index_sets
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    title: "test_index_set"
  register: index_set

- name: Update stream to use new index set
  graylog_streams:
    action: update
    endpoint: "{{ endpoint }}"
    graylog_user: "{{ graylog_user }}"
    graylog_password: "{{ graylog_password }}"
    stream_id: "{{ stream.json.id }}"
    index_set_id: "{{ index_set.json.id }}"
```

#### LDAP configuration
```
- name: Setup Active Directory authentication without SSL and set "Reader" as default role
  graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    enabled: "true"
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

- name: Remove current LDAP authentication configuration
  graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "delete"

-name: Get current LDAP authentication configuration
  graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"   
    action: "get"
  register: currentConfiguration

- name: Print current LDAP authentication configuration
  debug:
    msg: "{{ currentConfiguration }}"

- name: Test LDAP bind
  graylog_ldap:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "test"
    active_directory: "true"
    ldap_uri: "ldap://domaincontroller.mydomain.com:389"
    system_password_set: "true"
    system_username: "ldapbind@mydomain.com"
    system_password: "bindPassw0rd"
```

#### LDAP group mapping
```
- name: Get all LDAP groups
  graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "list"

- name: Get the LDAP group to Graylog role mapping
  graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"
    action: "list_mapping"

- name: Update the LDAP group to Graylog role mapping
  graylog_ldap_groups:
    endpoint: "graylog.mydomain.com"
    graylog_user: "username"
    graylog_password: "password"   
    action: "update"
    group: "{{ item.group }}"
    role: "{{ item.role }}"
  with_items:
    - { group : "ldap-group-admins", role : "Admin" }
    - { group : "ldap-group-read", role : "Reader" }
```

#### Input managment
```
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

  - name: Create Rsyslog TCP input
    graylog_input_syslog:
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

  - name: Create GELF HTTP input
    graylog_input_gelf:
      endpoint: "{{ graylog_endpoint }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      allow_http: "true"
      validate_certs: "false"
      action: "create"
      input_type: "HTTP"
      title: "Test input GELF HTTP"
      global_input: "true"
      bind_address: "0.0.0.0"

  - name: Update existing RSyslog input
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
```