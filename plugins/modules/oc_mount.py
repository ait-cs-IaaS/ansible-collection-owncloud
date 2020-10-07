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
module: oc_mounts
short_description: Manages ownCloud external mounts
description:
     -  |
          Manage ownCloud mounts. For the purposes of this module C(name) (alias=C(mount_point)) is used to uniquely identify mounts. 
          As such a users personal or the admin mounts cannot be configured to have more than one mount with a given C(mount_point).
version_added: '2.10.1'
options:
  name:
    description:
      - The path to use for the mount on the ownCloud server.
    type: str
    aliases: [mount_point]
    required: True
  user:
    description:
      - The uid of the user used for a personal mount. For a admin mount omit this option.
      - Mutually exclusive with C(users) and C(groups).
    type: str
    aliases: ['username']
  state:
    description:
      - The state the mount should be in (i.e., exist or not).
    choices: [ absent, present ]
    default: present
  users:
    description:
      - The users the mount should be available for.
      - Mutually exclusive with C(user).
    type: list
  groups:
    description:
      - The groups the mount should be available for.
      - Mutually exclusive with C(user).
    type: list
  authentication_backend:
    description:
      - The authentication backed to use for the mount.
    type: str
    choices: [sessioncredentials, none, password, oauth2, publickey]
    required: True
  storage_backend:
    description:
      - The storage backed to use for the mount.
    type: str
    choices: [dav, owncloud, sftp, googledrive, smb]
    required: True
  dav_config:
    description:
      - The WebDAV backend configuration options
    type: dict
    host:
      description:
        - Host address for the WebDAV server
      type: str
      required: True
    root:
      description:
        - The WebDAV directory to mount.
      type: str
      required: True
    secure:
      description:
        - Require secure connection or not
      type: bool
      default: False
  owncloud_config:
    description:
      - The ownCloud backend configuration options
    type: dict
    host:
      description:
        - Host address for the remote ownCloud server
      type: str
      required: True
    root:
      description:
        - The ownCloud directory to mount.
      type: str
      required: True
    secure:
      description:
        - Require secure connection or not
      type: bool
      default: False
  sftp_config:
    description:
      - The SFTP backend configuration options
    type: dict
    host:
      description:
        - Host address for the SFTP server
      type: str
      required: True
    root:
      description:
        - The remote directory to mount.
      type: str
      required: True
  smb_config:
    description:
      - The SMB / CIFS backend configuration options.
    type: dict
    host:
      description:
        - Host address for the SMB / CIFS server.
      type: str
      required: True
    share:
      description:
        - The SMB / CIFS share to mount.
      type: str
      required: True
    root:
      description:
        - The directory in the share to mount.
      type: str
    domain:
      description:
        - The domain to use for the SMB / CIFS share.
      type: str
  options:
    description:
      - The general mount options.
    type: dict
    encrypt:
      description:
        - Encrypt the mount or not.
      type: 'bool'
      default: True
    previews:
      description:
        - Generate preview thumbnails for the mounted files or not.
      type: 'bool'
      default: True
    filesystem_check_changes:
      description:
        -  When to check the remote file system for changes.
        - "0: Never (should only be used if the mount is never written to directly)"
        - "1: Once per direct access"
      type: 'int'
      default: 1
      choices: [0, 1]
    read_only:
      description:
        - Make the share read only or not.
      type: 'bool'
      default: False
    enable_sharing:
      description:
        - Allow files and directories in the mount to be shared or not.
      type: 'bool'
      default: False
    encoding_compatibility:
      description:
        - Enable compatibility with Mac NFD encoding (slow) or not.
      type: 'bool'
      default: False
  authentication_user:
    description:
      - The username to use for authorization for C(authentication_backend=password) and C(authentication_backend=publickey). 
    type: str
  authentication_password:
    description:
      - The password to use for authorization for C(authentication_backend=password). 
    type: str
    no_log: True
  oauth2_client_id:
    description:
      - The client id to use for authorization for C(authentication_backend=oauth2). 
    type: str
    no_log: True
  oauth2_client_secret:
    description:
      - The client secret to use for authorization for C(authentication_backend=oauth2). 
    type: str
    no_log: True
  private_key:
    description:
      - The RSA private key to use for authorization for C(authentication_backend=publickey). 
    type: str
    no_log: True
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
- oc_mount:
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


def _run_occ_cmd(module, cmd, chdir, out, err, commands, cmd_env=None):
  rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir, environ_update=cmd_env or {})
  out += out_occ
  err += err_occ
  if rc != 0:
      _fail(module, cmd, out_occ, err_occ)
  else:
      commands.append(cmd)
  return (out, err, out_occ, err_occ)

def _get_group_modifications(occ, module, chdir, name, groups, user_info):
  err = ''
  out = ''

  cmd = [occ] + ['group:list', '--output', 'json']
  rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
  out += out_occ
  err += err_occ

  if rc != 0:
    _fail(module, cmd, out, err)

  existing_groups = set(json.loads(out_occ))
  target_groups = set(groups)
  current_groups = set(user_info['groups'])

  # add all groups that are not yet assigned to the user
  add_groups = target_groups - current_groups
  # remove all groups they are currently assigned to that are not part of the new group list
  remove_groups = current_groups - target_groups  
  # create all new groups that do not exist on the system
  create_groups = add_groups - existing_groups

  return (add_groups, remove_groups, create_groups)


def _get_user_info(occ, module, chdir, name):
    err = ''
    out = ''

    cmd = [occ] + ['user:list', '--no-warnings', '--output', 'json', '-a', 'uid', '-a', 'displayName', '-a', 'email', '-a', 'enabled', name]
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
    user_info = json_out.get(name, {})

    # only get groups if the user exists
    if user_info:
      cmd = [occ] + ['user:list-groups', '--output', 'json', name]
      rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
      out += out_occ
      err += err_occ

      if rc != 0:
          _fail(module, cmd, out, err)
      
      user_groups = json.loads(out_occ)
      user_info['groups'] = user_groups

    return user_info

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
        msg += 'stdout: %s' % (out, )
    if err:
        msg += '\n:stderr: %s' % (err, )
    module.fail_json(cmd=cmd, msg=msg)


def main():
    state_map = dict(
        present=['user:add'],
        absent=['user:del']
    )

    dis_enable_map = dict()
    dis_enable_map[True] = ['user:enable']
    dis_enable_map[False] = ['user:disable']



    authentication_backends = {
      'sessioncredentials': 'password::sessioncredentials',
      'none': 'null::null',
      'password': 'password::password',
      'oauth2': 'oauth2::oauth2',
      'publickey': 'publickey::rsa'
    }

    storage_backend = {
        'dav': 'dav',
        'owncloud': 'owncloud',
        'sftp': 'sftp',
        'googledrive': 'googledrive',
        'smb':  'smb'
    }

                
    argument_spec = dict()
    argument_spec.update(
        name=dict(type='str', aliases=['mount_point'], required=True),
        state=dict(type='str', default='present', choices=state_map.keys()),
        user=dict(type='str', aliases=['username']),
        users=dict(type='list'),
        groups=dict(type='list'),
        authentication_backend=dict(type='str', choices=authentication_backends.keys(), required=True),
        storage_backend=dict(type='str', choices=storage_backend.keys(), required=True),
        dav_config=dict(
          type='dict',
          host=dict(type='str', required=True),
          root=dict(type='str', required=True),
          secure=dict(type='bool', default=False),
        ),
        owncloud_config=dict(
          type='dict',
          host=dict(type='str', required=True),
          root=dict(type='str', required=True),
          secure=dict(type='bool', default=False)
        ),
        sftp_config=dict(
          type='dict',
          host=dict(type='str', required=True),
          root=dict(type='str', required=True)
        ),
        smb_config=dict(
          type='dict',
          host=dict(type='str', required=True),
          share=dict(type='str', required=True),
          root=dict(type='str'),
          domain=dict(type='str')
        ),
        authentication_user=dict(type='str'),
        authentication_password=dict(type='str', no_log=True),
        oauth2_client_id=dict(type='str', no_log=True),
        oauth2_client_secret=dict(type='str', no_log=True),
        private_key=dict(type='str', no_log=True),
        options=dict(
          type='dict',
          encrypt=dict(type='bool', default=True),
          previews=dict(type='bool', default=True),
          filesystem_check_changes=dict(type='int', default=1, choices=[0, 1]),
          read_only=dict(type='bool', default=False),
          enable_sharing=dict(type='bool', default=False),
          encoding_compatibility=dict(type='bool', default=False)
        ),
        chdir=dict(type='path'),
        executable=dict(type='path'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
          [ 'authentication_backend', 'password', [ 'authentication_user', 'authentication_password' ]],
          [ 'authentication_backend', 'oauth2', [ 'oauth2_client_id', 'oauth2_client_secret' ]],
          [ 'authentication_backend', 'publickey', [ 'authentication_user', 'private_key' ]],
          [ 'storage_backend', 'dav', [ 'dav_config' ] ],
          [ 'storage_backend', 'owncloud', [ 'owncloud_config' ] ],
          [ 'storage_backend', 'sftp', [ 'sftp_config' ] ],
          [ 'storage_backend', 'smb', [ 'smb_config' ] ],
        ],
        mutually_exclusive=[
          ['user', 'users'],
          ['user', 'groups'],
          [
            'dav_config', 
            'owncloud_config',
            'sftp_config',
            'smb_config'
          ],
          ['']
        ],
        supports_check_mode=False,
    )

    state:str = module.params['state']
    mount_point:str = module.params['name']

    if chdir is None:
        # this is done to avoid permissions issues with privilege escalation
        chdir = tempfile.gettempdir()

    err = ''
    out = ''
    changed = ''

    occ = _get_occ(module, module.params['executable'])


    # module.exit_json(changed=changed, commands=commands, name=name, state=state,
    #                  stdout=out, stderr=err)



if __name__ == '__main__':
    main()