# Copyright 2014 Andrew Melton
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import os
import time

import netaddr
from novaclient import exceptions
import paramiko
from paramiko import client as paramiko_client
from paramiko import proxy as paramiko_proxy

DEFAULT_NICS = [
    {'net-id': '00000000-0000-0000-0000-000000000000'},
    {'net-id': '11111111-1111-1111-1111-111111111111'}
]


class NovaMikoException(Exception):
    pass


class InstanceNotFoundException(NovaMikoException):
    pass


class NoNetworkException(NovaMikoException):
    pass


class NovaMikoInstance(object):
    def __init__(self, nova, name, image, flavor, nics=DEFAULT_NICS,
                 config_drive=None, userdata=None,
                 ssh_connect_retry_limit=3,
                 nova_extras=None):
        self.nova = nova
        self.ssh = paramiko_client.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko_client.WarningPolicy())

        (self.instance,
         self.password) = self._create_instance(name, image, flavor, nics,
                                                config_drive=config_drive,
                                                userdata=userdata,
                                                nova_extras=nova_extras)

        self._ssh_connect(ssh_connect_retry_limit)

    def _create_instance(self, name, image, flavor, nics,
                         config_drive=None, userdata=None, nova_extras=None):
        return boot_instance(self.nova, name, image, flavor, nics,
                             config_drive=config_drive,
                             userdata=userdata,
                             sleep_after_build=15,
                             nova_extras=nova_extras)

    def _get_proxy_cmd(self, hostname):
        ssh_config_path = os.path.expanduser('~/.ssh/config')
        if os.path.exists(ssh_config_path):
            ssh_config = paramiko.SSHConfig()
            ssh_config.parse(open(ssh_config_path))
            host = ssh_config.lookup(hostname)
            if 'proxycommand' in host and host['proxycommand'] != 'none':
                return paramiko_proxy.ProxyCommand(host['proxycommand'])

    def _ssh_connect(self, retry_limit):
        kwargs = dict(username='root', password=self.password)

        address = get_public_ipv4(self.instance)
        if not address:
            raise NoNetworkException()

        proxy_cmd = self._get_proxy_cmd(address)
        if proxy_cmd:
            kwargs['sock'] = proxy_cmd
        retry = 0
        connected = False
        while not connected:
            try:
                self.ssh.connect(address, **kwargs)
                connected = True
            except paramiko.SSHException:
                retry += 1
                if retry == retry_limit:
                    raise
                time.sleep(5)

    def _add_paths(self, cmd):
        paths = [
            '/usr/local/sbin',
            '/usr/local/bin',
            '/usr/sbin/',
            '/usr/bin/',
            '/sbin',
            '/bin'
        ]
        paths_str = ':'.join(paths)
        return 'PATH={} {}'.format(paths_str, cmd)

    def exec_streams(self, cmd, timeout=None):
        return self.ssh.exec_command(self._add_paths(cmd), timeout=timeout)

    def exec_out(self, cmd, timeout=None):
        std_in, std_out, std_err = self.exec_streams(cmd, timeout=timeout)
        std_in.close()
        return std_out.readlines()

    def exec_return_code(self, cmd, timeout=None):
        session = self.ssh.get_transport().open_session()
        session.exec_command(self._add_paths(cmd), timeout=timeout)
        return session.recv_exit_status()

    def destroy(self):
        self.ssh.close()
        self.instance.delete()


class StatusTimoutException(Exception):
    def __init__(self, instance, expected_status):
        msg = 'Instance(%(instance_uuid)s, %(instance_status)s) ' \
              'timed out waiting for status %(expected_status)s'
        msg = msg % dict(instance_uuid=instance.id,
                         instance_status=instance.status,
                         expected_status=expected_status)
        super(StatusTimoutException, self).__init__(msg)


def wait_for_status(instance, status='ACTIVE', timeout=300):
    time.sleep(1)
    instance.get()
    start = datetime.datetime.utcnow()
    timeout_delta = datetime.timedelta(seconds=timeout)
    while instance.status != status:

        if ((datetime.datetime.utcnow() - start) > timeout_delta or
                instance.status == 'ERROR'):
            raise StatusTimoutException(instance, status)

        time.sleep(10)
        try:
            instance.get()
        except exceptions.NotFound:
            if status == 'DELETED':
                return


def boot_instance(nova, name, image, flavor,
                  nics=DEFAULT_NICS,
                  config_drive=None, userdata=None,
                  sleep_after_build=45,
                  nova_extras=None):

    nova_extras = nova_extras or dict()

    server = nova.servers.create(name, image, flavor,
                                 nics=nics, config_drive=config_drive,
                                 userdata=userdata, **nova_extras)

    admin_password = server.adminPass

    wait_for_status(server)
    time.sleep(sleep_after_build)
    return server, admin_password


def get_public_ipv4(instance):
        for addr in instance.networks['public']:
            if netaddr.valid_ipv4(addr):
                return addr


def get_public_ipv6(instance):
    for addr in instance.networks['public']:
        if netaddr.valid_ipv6(addr):
            return addr


def get_private_ipv4(instance):
        for addr in instance.networks['private']:
            if netaddr.valid_ipv4(addr):
                return addr
