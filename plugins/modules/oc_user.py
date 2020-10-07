#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Maximilian <maximilian.frank@ait.ac.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: oc_user
short_description: Manages ownCloud users
description:
     - "Manage ownCloud users. C(name) defines the uid. C(password) is required to create a new user."
version_added: "2.10.1"
options:
  name:
    description:
      - The uid of the users to be configured.
    type: str
    aliases: ['username']
  state:
    description:
      - The state the user should be in (i.e., exist or not).
    choices: [ absent, present ]
    default: present
  enabled:
    description:
      - Enabled/disable the user.
    type: bool
    default: 'yes'
  display_name:
    description:
      - The display name to be used for the user.
    type: str
    aliases: ['displayName']
  email:
    description:
      - The email address for the user.
    type: str
  groups:
    description:
      - The groups the user should be added to (The group will be created if it does not exist).
    type: list
  password:
    description:
      - The password to set when the user is created. (Use C(force_password) if you want to change the password of an existing user) 
    type: str
  force_password:
    description:
      - Always change the user password.
    type: bool
    default: 'no'
  chdir:
    description:
      - cd into this directory before running the command
  executable:
    description:
      - The explicit executable or a pathname to the executable to be used to
        run occ.
requirements:
  - occ
author:
  - Maximilian Frank
'''

EXAMPLES = '''
# Install contacts app.
- oc_user:
    name: alice
    password: safe_password
'''

RETURN = '''
name:
  description: name the user added to ownCloud
  returned: success
  type: str
  sample: 'alice'
'''

import os
import json
import tempfile
import traceback
import shutil

import xml.etree.ElementTree as ET

from ansible.module_utils.basic import AnsibleModule


def _get_user_info(occ, module, chdir, name):
    err = ''
    out = ''

    cmd = [occ] + ['user:list', '--no-warnings', '--output', 'json', "-a", "uid", "-a", "displayName", "-a", "email", "-a", "enabled", name]
    rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
    out += out_occ
    err += err_occ

    json_out = json.loads(out_occ)

    if rc != 0:
        _fail(module, cmd, out, err)

    module.log(msg=out_occ)
    
    # nothing was returned with our search time
    if type(json_out) == list:
        return {}

    # return empty dict if our specifc user does not exist
    return json_out.get(name, {})

def _get_occ(module, executable=None):
    candidate_occ_basenames = ('occ',)
    occ = None
    if executable is not None:
        if os.path.isabs(executable):
            occ = executable
        else:
            candidate_occ_basenames = (executable,)

    if occ is None:
        for basename in candidate_occ_basenames:
            occ = module.get_bin_path(basename, False, opt_dirs=['/usr/local/bin'])
            if occ is not None:
                break
        else:
            # For-else: Means that we did not break out of the loop
            # (therefore, that occ was not found)
            module.fail_json(msg='Unable to find any of %s to use. occ'
                                 ' needs to be installed.' % ', '.join(candidate_occ_basenames))

    return occ



def _fail(module, cmd, out, err):
    msg = ''
    if out:
        msg += "stdout: %s" % (out, )
    if err:
        msg += "\n:stderr: %s" % (err, )
    module.fail_json(cmd=cmd, msg=msg)


def main():
    state_map = dict(
        present=['user:add'],
        absent=['user:del']
    )

    dis_enable_map = dict()
    dis_enable_map[True] = ["user:enable"]
    dis_enable_map[False] = ["user:disable"]


    argument_spec = dict()
    argument_spec.update(
        state=dict(type='str', default='present', choices=state_map.keys()),
        name=dict(type='str', aliases=['username'], no_log=False),
        enabled=dict(type='bool', default=True),
        display_name=dict(type='str', aliases=['displayName']),
        email=dict(type='str'),
        groups=dict(type='list'),
        password=dict(type='str', no_log=True),
        force_password=dict(type='bool', default=False, no_log=False),
        chdir=dict(type='path'),
        executable=dict(type='path'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[['name']],
        mutually_exclusive=[['name']],
        supports_check_mode=False,
    )

    state:str = module.params['state']
    name:str = module.params['name']
    enable:bool = module.params['enabled']
    display_name:str = module.params['display_name']
    email:str = module.params['email']
    groups:List[str] = module.params['groups']
    password:str = module.params['password']
    force_password:bool = module.params['force_password']
    chdir = module.params['chdir']

    if chdir is None:
        # this is done to avoid permissions issues with privilege escalation
        chdir = tempfile.gettempdir()

    err = ''
    out = ''
    changed = ''

    occ = _get_occ(module, module.params['executable'])


    user_info = _get_user_info(occ, module, chdir, name)

    # if we get an empty dict the user does not exist
    user_exists = bool(user_info)

    run_cmd = (user_exists and state == "absent") or (not user_exists and state == "present")
    run_modify_display_name = display_name is not None and state == "present" and user_exists and display_name != user_info['displayName']
    run_modify_email = email is not None and state == "present" and user_exists and email != user_info['email']    
    run_dis_enable = (user_exists and enable != user_info.get('enabled', False)) or (not user_exists and not enable)
    
    # set add or del command
    commands = []
    user_cmd = [occ] + state_map[state]
    modify_cmd = [occ] + ["user:modify", name]
    dis_enable_cmd = [occ] + dis_enable_map[enable]
    pw_reset_cmd = [occ] + ["user:resetpassword", "--password-from-env"]
    

    if run_cmd:
        cmd_env = dict()
        cmd = user_cmd
        if state == "present":
          if password is not None:
            cmd.append("--password-from-env")
            cmd_env['OC_PASS'] = password
          else:
            module.fail_json(
              user=name,
              msg=["Password is required to create a new user!"],
            )
          
          if display_name is not None:
            cmd.append("--display-name")
            cmd.append(display_name)

          if email is not None:
            cmd.append("--email")
            cmd.append(email)

          if groups is not None:
            for group in groups:
              cmd.append("--group")
              cmd.append(group)

        cmd.append(name)

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir, environ_update=cmd_env)
        out += out_occ
        err += err_occ
        if rc != 0:
            _fail(module, cmd, out_occ, err_occ)
        else:
            changed += out_occ
            commands.append(cmd)

    if run_modify_display_name:
        cmd = modify_cmd+["displayname", display_name]
        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        if rc != 0:
            _fail(module, cmd, out_occ, err_occ)
        else:
            changed += out_occ
            commands.append(cmd)
    
    if run_modify_email:
        cmd = modify_cmd+["email", email]
        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        if rc != 0:
            _fail(module, cmd, out_occ, err_occ)
        else:
            changed += out_occ
            commands.append(cmd)

    if run_dis_enable:
        cmd = dis_enable_cmd + [name]
        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        if rc != 0:
            _fail(module, cmd, out_occ, err_occ)
        else:
            changed += name+" has been "
            changed += "enabled\n" if enable else "disabled\n"
            commands.append(cmd)
        
    if user_exists and force_password:
        if password is not None:
          cmd_env = { 'OC_PASS': password }
          cmd = pw_reset_cmd + [name]
          rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir, environ_update=cmd_env)
          out += out_occ
          err += err_occ
          if rc != 0:
              _fail(module, cmd, out_occ, err_occ)
          else:
              changed += out_occ
              commands.append(cmd)
        else:
          module.fail_json(
              user=name,
              msg=["Password is required when force_password is active!"],
            )


    module.exit_json(changed=changed, commands=commands, name=name, state=state,
                     stdout=out, stderr=err)


if __name__ == '__main__':
    main()