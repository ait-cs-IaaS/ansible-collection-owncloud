#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Maximilian <maximilian.frank@ait.ac.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
import xml.etree.ElementTree as ET
import shutil
import traceback
import tempfile
import json
import os
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: oc_group
short_description: Manages a ownCloud group
description:
     -  Manage a ownCloud group. A group can be created or deleted and users can be added or removed.
     -  Note that it is not possible to manage group admins yet since this is not supported by the occ command.
          
version_added: '2.10.1'
options:
  name:
    description:
      - The name of the group.
    type: str
    aliases: [group]
    required: True
  state:
    description:
      - The state the group should be in (i.e., exist or not).
    choices: [ absent, present ]
    default: present
  users:
    description:
      - The users that should be part of the group.
    type: list
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
# Create group finance with users bob and alice
- oc_group:
    name: finance
    state: present
    users: 
      - bob
      - alice
'''

RETURN = '''
name:
  description: name of the group added or removed
  returned: success
  type: str
  sample: 'finance'
users:
  description: list of users part of the group
  returned: success
  type: list
  sample: 
    - bob 
    - alice
commands:
  description: list of occ commands used to modify the group
  returned: success
  type: list
  sample: 
    - '["occ", "group:add-member", "--member", "alice", "admin"]'
'''


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
            occ = module.get_bin_path(
                basename, False, opt_dirs=['/usr/local/bin'])
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
        msg += 'stdout: %s' % (out, )
    if err:
        msg += '\n:stderr: %s' % (err, )
    module.fail_json(cmd=cmd, msg=msg)

def _get_group_info(occ, module, chdir, group):
    # first check if group exists
    out = ''
    err = ''

    cmd = [occ] + ['group:list', '--output', 'json', '--no-warnings', group]

    rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
    out += out_occ
    err += err_occ

    if rc != 0:
        _fail(module, cmd, out, err)
    else:
      groups = json.loads(out_occ)
      # if the group is not in the list it does not yet exist
      if group not in groups:
        return None

    # if the group exists we can get its members
    cmd = [occ] + ['group:list-members', '--output', 'json', '--no-warnings', group]

    rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
    out += out_occ
    err += err_occ

    if rc != 0:
        _fail(module, cmd, out, err)
    else:
      return json.loads(out_occ)

def _remove_group(occ, module, chdir, group, users, group_info):
    out = ''
    err = ''
    changed = []
    commands = []

    # only need to delete if it actually exists
    if group_info:
      cmd = [occ] + ['group:delete', group]

      rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
      commands.append(cmd)
      out += out_occ
      err += err_occ

      if rc != 0:
          _fail(module, cmd, out, err)
      else:
          changed.append('The group "%s" was deleted!' % group)


    return (changed, commands, out, err)


def _update_group(occ, module, chdir, group, users, group_info):
    out = ''
    err = ''
    changed = []
    commands = []
    users_to_add = []
    users_to_remove = []
    
    # check if we have to remove or add users to existing group
    if group_info:
        # we only modify users if the ansible option is passed
        if users is not None:
            target_users_set = set(users)
            current_users_set = set(group_info.keys())
            users_to_add = list(target_users_set - current_users_set)
            users_to_remove = list(current_users_set - target_users_set)
    # create group 
    else:
        cmd = [occ] + ['group:add', group]

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        commands.append(cmd)
        out += out_occ
        err += err_occ

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            changed.append(out_occ)
            # if the group is new we have to add all users
            users_to_add = users or []


    if users_to_add:
        cmd = [occ] + ['group:add-member']
        for user in users_to_add:
            cmd += ['--member', user]
        cmd += [group]

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        commands.append(cmd)
        out += out_occ
        err += err_occ

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            changed.append("Added users %s to group %s" % (','.join(users_to_add), group))

    if users_to_remove:
        cmd = [occ] + ['group:remove-member']
        for user in users_to_remove:
            cmd += ['--member', user]
        cmd += [group]
        
        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        commands.append(cmd)
        out += out_occ
        err += err_occ

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            changed.append("Removed users %s from group %s" % (','.join(users_to_add), group))
      
    return (changed, commands, out, err)


def main():
    # map controling which function to call for the given state
    states = dict(
        absent=_remove_group,
        present=_update_group
    )

    argument_spec = dict()
    argument_spec.update(
        name=dict(type='str', aliases=['group'], required=True),
        state=dict(type='str', default='present', choices=states.keys()),
        users=dict(type='list'),
        chdir=dict(type='path'),
        executable=dict(type='path'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    state = module.params['state']
    group = module.params['name']
    users = module.params['users']
    chdir = module.params['chdir']

    if chdir is None:
        # this is done to avoid permissions issues with privilege escalation
        chdir = tempfile.gettempdir()

    occ = _get_occ(module, module.params['executable'])

    group_info = _get_group_info(occ, module, chdir, group)

    # apply the change
    (changed, commands, out, err) = states[state](occ, module, chdir, group, users, group_info)

    module.exit_json(changed=changed, commands=commands, name=group, users=users, state=state,
                     stdout=out, stderr=err)


if __name__ == '__main__':
    main()
