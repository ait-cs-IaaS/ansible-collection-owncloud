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
      - The uid of the user used for a personal mount. For a admin mount, that can be assigned to multiple users and groups, omit this option.
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
    choices: [sessioncredentials, password, oauth2, publickey]
    required: True
  storage_backend:
    description:
      - The storage backed to use for the mount.
      - C(dav) supports authentication backends C(sessioncredentials), C(password)
      - C(owncloud) supports authentication backends C(sessioncredentials), C(password)
      - C(sftp) supports authentication backends  C(sessioncredentials), C(password), C(publickey)
      - C(googledrive) supports authentication backend C(oauth2)
      - C(smb) supports authentication backends C(sessioncredentials), C(password)
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


# map authentication backend name to its ownCloud identifier
authentication_backends = {
    'sessioncredentials': {
        'identifier': 'password::sessioncredentials',
        'configuration': {}
    },
    'password': {
        'identifier': 'password::password',
        'configuration': {
            'authentication_user': 'user',
            'authentication_password': 'password'
        }
    },
    'oauth2': {
        'identifier': 'oauth2::oauth2',
        'configuration': {
            'oauth2_client_id': 'client_id',
            'oauth2_client_secret': 'client_secret'
        }
    },
    'publickey': {
        'identifier': 'publickey::rsa',
        'configuration': {
            'authentication_user': 'user',
            'private_key': 'public_key'
        }
    }
}

# storage backend information e.g., supported authentication backends etc.
storage_backends = {
    'dav': {
        'name': 'WebDAV',
        'identifier': 'dav',
        'configuration': 'dav_config',
        'storage_class': '\\OC\\Files\\Storage\\DAV',
        'supported_authentication_backends': [
            'password::sessioncredentials',
            'password::password'
        ]
    },
    'owncloud': {
        'name': 'ownCloud',
        'identifier': 'owncloud',
        'configuration': 'owncloud_config',
        'storage_class': '\\OCA\\Files_External\\Lib\\Storage\\OwnCloud',
        'supported_authentication_backends': [
            'password::sessioncredentials',
            'password::password'
        ]
    },
    'sftp': {
        'name': 'SFTP',
        'identifier': 'sftp',
        'configuration': 'sftp_config',
        'storage_class': '\\OCA\\Files_External\\Lib\\Storage\\SFTP',
        'supported_authentication_backends': [
            'password::sessioncredentials',
            'password::password',
            'publickey::rsa'
        ]
    },
    'smb': {
        'name': 'SMB \/ CIFS',
        'identifier': 'smb',
        'configuration': 'smb_config',
        'storage_class': '\\OCA\\Files_External\\Lib\\Storage\\SMB',
        'supported_authentication_backends': [
            'password::sessioncredentials',
            'password::password'
        ]
    },
    'googledrive': {
        'name': 'Google Drive',
        'identifier': 'googledrive',
        'configuration': None,
        'storage_class': '\\OCA\\Files_External\\Lib\\Storage\\Google',
        'supported_authentication_backends': [
            'oauth2::oauth2'
        ]
    }
}


def _run_occ_cmd(module, cmd, chdir, out, err, commands, cmd_env=None):
    rc, out_occ, err_occ = module.run_command(
        cmd, cwd=chdir, environ_update=cmd_env or {})
    out += out_occ
    err += err_occ
    if rc != 0:
        _fail(module, cmd, out_occ, err_occ)
    else:
        commands.append(cmd)
    return (out, err, out_occ, err_occ)


def _get_mount_info(occ, module, chdir, name, user):
    cmd = [occ] + ['files_external:list', '--no-warnings', '--full',
                   '-i', '--mount-options',
                   '--show-password', '--output', 'json']

    if user is not None:
        cmd += [user]

    err = ''
    out = ''

    # first get general mount info with mount config
    rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
    out += out_occ
    err += err_occ

    if rc != 0:
        _fail(module, cmd, out, err)

    mounts = json.loads(out_occ)

    # prepend mandetory slash if not present
    if name[0] != "/":
        name = "/" + name
    filtered_mounts = (item for item in mounts if item["mount_point"] == name)
    mount_info = next(filtered_mounts, None)

    if next(filtered_mounts, None) is not None:
        module.warn('Multiple mounts with name (mount_point) "%s" found! Using the mount with mount_id: %d' % (
            name, mount_info['mount_id']))

    # the options field is returned as string with comma separeted `key: val` fields
    # so we have to convert it manually
    if mount_info is not None:
        options = {}
        for option in mount_info['options'].split(', '):
            (key, val) = option.split(':')
            options[key] = json.loads(val)
        mount_info['options'] = options

    return mount_info


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


def _remove_mount(occ, module, chdir, storage_backend, authentication_backend, mount_info):
    out = ''
    err = ''
    changed = []
    commands = []
    mount_id = None

    # we only have to do something if the mount actually exists
    if mount_info:
        mount_id = mount_info['mount_id']
        cmd = [occ] + ['files_external:delete', '--yes', str(mount_id)]

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        commands.append(cmd)

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            changed.append('Removed mount "%s" with mount_id %d.' %
                           (mount_info['mount_point'], mount_id))

    return (changed, commands, mount_id, out, err)


def _update_mount(occ, module, chdir, storage_backend, authentication_backend, mount_info):
    out = ''
    err = ''
    changed = []
    commands = []
    mount_id = None

    mount_point = module.params['name']
    user = module.params['user']

    # if we currently have a mount on the given mount point
    # we have to check if it using the same backends if not we have to delete it and re-add it.
    if mount_info and (storage_backend['storage_class'] != mount_info['storage'] or authentication_backend['identifier'] != mount_info['authentication_type']):
        (changed, commands, _, out, err) = _remove_mount(occ, module,
                                                         chdir, storage_backend, authentication_backend, mount_info)
        # set mount to non existant after delete
        mount_info = {}

    mount_config = module.params[storage_backend['configuration']]

    # dict containing the mount options that need to be reconfigured
    owncloud_mount_options = {}
    # dict containing backend config options that need to be reconfigured
    config_to_change = {}
    # users and groups to dis-/allow access to the mount
    users_to_grant = []
    users_to_remove = []
    groups_to_grant = []
    groups_to_remove = []

    # check if we need to update the existing mount
    if mount_info:
        # set mount_id for updates
        mount_id = mount_info['mount_id']

        # check for storage backend config updates
        for config_option, val in mount_config.items():
            if val is not None and val != mount_info['configuration'][config_option]:
                config_to_change[config_option] = val

        # check for auth backend config updates
        for ansible_option, occ_option in authentication_backend['configuration'].items():
            val = module.params[ansible_option]
            if val is not None and val != mount_info['configuration'][occ_option]:
                config_to_change[occ_option] = val

        # check for owncloud mount option updates
        for mount_option, val in (module.params.get('options') or {}).items():
            if val is not None and val != mount_info['options'][mount_option]:
                owncloud_mount_options[mount_option] = val

        # setting users and groups is only possible for admin mounts
        if user is None:
            current_users_set = set(mount_info['applicable_users'])
            target_users_set = set(module.params.get('users') or [])
            users_to_grant = list(target_users_set - current_users_set)
            users_to_remove = list(current_users_set - target_users_set)

            current_groups_set = set(mount_info['applicable_groups'])
            target_groups_set = set(module.params.get('groups') or [])
            groups_to_grant = list(target_groups_set - current_groups_set)
            groups_to_remove = list(current_groups_set - target_groups_set)

    # add new mount since it does not exist yet
    else:
        cmd = [occ] + ['files_external:create', '--output', 'json']
        cmd += _make_mount_config(mount_config)
        cmd += _make_auth_config(module,
                                 authentication_backend['configuration'])
        if user is not None:
            cmd += ['--user', user]
        cmd += [mount_point, storage_backend['identifier'],
                authentication_backend['identifier']]

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        commands.append(cmd)

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            changed.append('Storage created with id ' + out_occ)
            # default values might be different depending on install
            # so we just set each option given to us manually on create
            owncloud_mount_options = module.params.get('options') or {}

            # since this is a new mount we have to add all defined users and groups
            users_to_grant = module.params.get('users') or []
            groups_to_grant = module.params.get('groups') or []
            mount_id = out_occ

    # update the auth and storage backend options
    if config_to_change:
        base_cmd = [occ, 'files_external:config', str(mount_id)]
        for option, val in config_to_change.items():
            if val is not None:
                # occ interpertrates all input other than 'true' as false (case sensitive)
                # str(True) would result in 'True'
                if type(val) == bool:
                    val = str(val).lower()
                cmd = base_cmd + [option, str(val)]
                rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
                out += out_occ
                err += err_occ
                commands.append(cmd)

                if rc != 0:
                    _fail(module, cmd, out, err)
                else:
                    changed.append('Changed config "%s" to "%s" on mount_id "%s"' % (
                        option, str(val), str(mount_id)))

    # update the ownCloud mount options (e.g., enable_sharing, etc.)
    if owncloud_mount_options:
        base_cmd = [occ, 'files_external:option', str(mount_id)]
        for option, val in owncloud_mount_options.items():
            if val is not None:
                # occ interpertrates all input other than 'true' as false (case sensitive)
                # str(True) would result in 'True'
                if type(val) == bool:
                    val = str(val).lower()
                cmd = base_cmd + [option, str(val)]
                rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
                out += out_occ
                err += err_occ
                commands.append(cmd)

                if rc != 0:
                    _fail(module, cmd, out, err)
                else:
                    changed.append('Changed option "%s" to "%s" on mount_id "%s"' % (
                        option, str(val), str(mount_id)))

    # add users and groups to share
    if users_to_grant or groups_to_grant:
        cmd = [occ, 'files_external:applicable', '--output', 'json']
        for user in users_to_grant:
            cmd += ['--add-user', user]
        for group in groups_to_grant:
            cmd += ['--add-group', group]
        cmd += [str(mount_id)]

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        commands.append(cmd)

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            if users_to_grant:
                changed.append("Added users %s to mount with mount_id %s" % (
                    ', '.join(users_to_grant), mount_id))
            if groups_to_grant:
                changed.append("Added groups %s to mount with mount_id %s" % (
                    ', '.join(groups_to_grant), mount_id))

    # remove users and groups from share
    if users_to_remove or groups_to_remove:
        cmd = [occ, 'files_external:applicable', '--output', 'json']
        for user in users_to_remove:
            cmd += ['--remove-user', user]
        for group in groups_to_remove:
            cmd += ['--remove-group', group]
        cmd += [str(mount_id)]

        rc, out_occ, err_occ = module.run_command(cmd, cwd=chdir)
        out += out_occ
        err += err_occ
        commands.append(cmd)

        if rc != 0:
            _fail(module, cmd, out, err)
        else:
            if users_to_remove:
                changed.append("Removed users %s form mount with mount_id %s" % (
                    ', '.join(users_to_remove), mount_id))
            if groups_to_remove:
                changed.append("Removed groups %s form mount with mount_id %s" % (
                    ', '.join(groups_to_remove), mount_id))

    return (changed, commands, mount_id, out, err)


def _make_mount_config(mount_config):
    options = []
    for key, val in mount_config.items():
        if val is not None:
            # occ interpertrates all input other than 'true' as false (case sensitive)
            # str(True) would result in 'True'
            if type(val) == bool:
                val = str(val).lower()
            options += ['-c', '%s=%s' % (key, str(val))]
    return options


def _make_auth_config(module, auth_config_definition):
    options = []
    for ansible_option, occ_key in auth_config_definition.items():
        val = module.params[ansible_option]
        if val is not None:
            # occ interpertrates all input other than 'true' as false (case sensitive)
            # str(True) would result in 'True'
            if type(val) == bool:
                val = str(val).lower()
            options += ['-c', '%s=%s' % (occ_key, str(val))]
    return options


def main():
    # map controling which function to call for the given state
    states = dict(
        absent=_remove_mount,
        present=_update_mount
    )

    argument_spec = dict()
    argument_spec.update(
        name=dict(type='str', aliases=['mount_point'], required=True),
        state=dict(type='str', default='present', choices=states.keys()),
        user=dict(type='str', aliases=['username']),
        users=dict(type='list'),
        groups=dict(type='list'),
        authentication_backend=dict(
            type='str', choices=authentication_backends.keys(), required=True),
        storage_backend=dict(
            type='str', choices=storage_backends.keys(), required=True),
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
            filesystem_check_changes=dict(
                type='int', default=1, choices=[0, 1]),
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
            ['authentication_backend', 'password', [
                'authentication_user', 'authentication_password']],
            ['authentication_backend', 'oauth2', [
                'oauth2_client_id', 'oauth2_client_secret']],
            ['authentication_backend', 'publickey', [
                'authentication_user', 'private_key']],
            ['storage_backend', 'dav', ['dav_config']],
            ['storage_backend', 'owncloud', ['owncloud_config']],
            ['storage_backend', 'sftp', ['sftp_config']],
            ['storage_backend', 'smb', ['smb_config']],
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

    state = module.params['state']
    name = module.params['name']
    user = module.params['user']
    storage_backend = module.params['storage_backend']
    authentication_backend = module.params['authentication_backend']
    chdir = module.params['chdir']

    if authentication_backends[authentication_backend]['identifier'] not in storage_backends[storage_backend]['supported_authentication_backends']:
        _fail(module, None, '', 'Authentication backend "%s" not supported for storage backend "%s"' % (
            authentication_backend, storage_backend))

    if chdir is None:
        # this is done to avoid permissions issues with privilege escalation
        chdir = tempfile.gettempdir()

    occ = _get_occ(module, module.params['executable'])

    mount_info = _get_mount_info(occ, module, chdir, name, user)

    # apply the change
    (changed, commands, mount_id, out, err) = states[state](
        occ, module, chdir, storage_backends[storage_backend], authentication_backends[authentication_backend], mount_info)

    module.exit_json(changed=changed, commands=commands, name=name, mount_id=mount_id, state=state,
                     stdout=out, stderr=err)


if __name__ == '__main__':
    main()
