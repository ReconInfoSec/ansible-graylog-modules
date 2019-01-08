# ansible-graylog-modules
Ansible modules for the Graylog API

### Modules

There are currently 3 modules with the following actions:

* graylog_users
  * create
  * update - updates username, email, full_name, password, roles, permissions, timezone
  * delete
  * list
* graylog_roles
  * create
  * update - updates name, description, permissions, read_only
  * delete
  * list

### Examples

More examples can be found in `main.yml`.

#### Create User

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

#### Create Role

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
