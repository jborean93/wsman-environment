from __future__ import annotations

import typing as t

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    def run(
        self,
        tmp: str | None = None,
        task_vars: dict[str, t.Any] | None = None,
    ) -> dict[str, t.Any]:
        result = super().run(tmp=tmp, task_vars=task_vars)
        del tmp

        task_vars = task_vars or {}

        domain_realm = task_vars["domain_realm"]
        domain_user = f'{task_vars["domain_username"]}@{domain_realm.upper()}'
        domain_password = task_vars["domain_password"]
        target_host = f'test.{domain_realm}'

        cert_base_port = int(task_vars['certificate_base_port'])
        cert_info = task_vars['certificate_info']
        http_port = cert_base_port + (len(cert_info) * 4)

        proxy_info = task_vars["proxy_info"]
        socks_info = task_vars["socks_info"]

        hosts: dict[str, dict[str, t.Any]] = {}
        groups: dict[str, dict[str, t.Any]] = {
            'http': {
                'hosts': {},
                'vars': {
                    'ansible_port': http_port,
                    'ansible_psrp_protocol': 'http',
                }
            },
            'http_through_proxy': {
                'hosts': {},
                'vars': {
                    'ansible_port': http_port + 2,
                    'ansible_psrp_protocol': 'http',
                },
            },
            'https': {
                'hosts': {},
                'vars': {
                    'ansible_port': cert_base_port,
                    'ansible_psrp_protocol': 'https',
                    'ansible_psrp_ca_cert': 'ca.pem',
                },
            },
            'https_through_proxy': {
                'hosts': {},
                'vars': {
                    'ansible_port': cert_base_port + 2,
                    'ansible_psrp_protocol': 'https',
                    'ansible_psrp_ca_cert': 'ca.pem',
                },
            },
            'basic': {
                'hosts': {},
                'vars': {
                    'ansible_psrp_auth': 'basic',
                    'ansible_user': task_vars['local_username'],
                    'ansible_password': task_vars['local_password'],
                    'ansible_psrp_message_encryption': 'never',
                },
            },
            'certificate': {
                'hosts': {},
                'vars': {
                    'ansible_psrp_auth': 'certificate',
                    'ansible_psrp_certificate_pem': 'client_auth.pem',
                    'ansible_psrp_certificate_key_pem': 'client_auth.key',
                },
            },
            'kerberos': {
                'hosts': {},
                'vars': {
                    'ansible_psrp_auth': 'kerberos',
                    'ansible_user': domain_user,
                    'ansible_password': domain_password,
                },
            },
            'negotiate': {
                'hosts': {},
                'vars': {
                    'ansible_psrp_auth': 'negotiate',
                    'ansible_user': domain_user,
                    'ansible_password': domain_password,
                },
            },
            'ntlm': {
                'hosts': {},
                'vars': {
                    'ansible_psrp_auth': 'ntlm',
                    'ansible_user': domain_user,
                    'ansible_password': domain_password,
                },
            },
            'credssp': {
                'hosts': {},
                'vars': {
                    'ansible_psrp_auth': 'credssp',
                    'ansible_user': domain_user,
                    'ansible_password': domain_password,
                },
            },
        }

        proxy_host = f"squid.{domain_realm}"
        for proxy_scheme in ["http", "https"]:
            for proxy in proxy_info:
                proxy_auth = proxy['auth']
                proxy_port = int(proxy['port'])

                proxy_vars: dict[str, t.Any] = {}

                if proxy_scheme == 'https':
                    proxy_vars['ansible_psrp_proxy_ca_cert'] = 'ca.pem'
                    proxy_port += 1

                proxy_vars['ansible_psrp_proxy'] = f"{proxy_scheme}://{proxy_host}:{proxy_port}/"

                if proxy_auth == 'anon':
                    proxy_suffix = ''
                else:
                    proxy_suffix = f'_{proxy_auth}'

                if proxy_auth == 'basic':
                    proxy_vars['ansible_psrp_proxy_user'] = task_vars['proxy_username']
                    proxy_vars['ansible_psrp_proxy_password'] = task_vars['proxy_password']

                elif proxy_auth == 'ldap':
                    proxy_vars['ansible_psrp_proxy_user'] = task_vars["domain_username"]
                    proxy_vars['ansible_psrp_proxy_password'] = domain_password

                elif proxy_auth == 'kerb':
                    proxy_vars['ansible_psrp_proxy_user'] = domain_user
                    proxy_vars['ansible_psrp_proxy_password'] = domain_password
                    proxy_vars['ansible_psrp_proxy_auth'] = 'negotiate'

                groups[f"proxy_{proxy_scheme}{proxy_suffix}"] = {
                    "hosts": {},
                    "vars": proxy_vars,
                }

        for socks_scheme in ["socks5", "socks5h"]:
            for socks in socks_info:
                socks_auth = socks['auth']
                socks_port = int(socks['port'])

                socks_vars: dict[str, t.Any] = {
                    'ansible_psrp_proxy': f"{socks_scheme}://{proxy_host}:{socks_port}",
                }

                if socks_scheme == "socks5h":
                    socks_vars['ansible_host'] = f'remote-res.{domain_realm}'
                    socks_vars['ansible_psrp_negotiate_hostname_override'] = target_host

                socks_suffix = ''
                if socks_auth == "basic":
                    socks_suffix = '_basic'
                    socks_vars['ansible_psrp_proxy_user'] = socks["username"]
                    socks_vars['ansible_psrp_proxy_password'] = socks['password']

                groups[f"proxy_{socks_scheme}{socks_suffix}"] = {
                    "hosts": {},
                    "vars": socks_vars,
                }

        # These are once off hosts for custom tests
        hosts['http_vanilla'] = {'ansible_port': 5985}
        self._add_to_groups(groups, 'http_vanilla', ['http', 'negotiate'])

        hosts['https_vanilla'] = {'ansible_port': 5986}
        self._add_to_groups(groups, 'https_vanilla', ['https', 'negotiate'])

        hosts['jea'] = {'ansible_psrp_configuration_name': 'JEA'}
        self._add_to_groups(groups, 'jea', ['http', 'negotiate'])

        # These are hosts for CBT tests
        for idx, cert in enumerate(cert_info):
            host_name = f'https_cbt_{cert["test"]}'
            host_opts: dict[str, t.Any] = {'ansible_port': cert_base_port + (idx * 4)}
            if (
                cert.get('self_signed', False) or
                cert.get('subject', '') or
                cert.get('algorithm', '') in ['sha1', 'sha512-pss']
            ):
                host_opts['ansible_psrp_cert_validation'] = 'ignore'
            elif not cert.get('system_ca', True):
                host_opts['ansible_psrp_ca_cert'] = 'ca_explicit.pem'

            hosts[host_name] = host_opts
            self._add_to_groups(groups, host_name, ['https', 'negotiate'])

        for scheme in ["http", "https"]:
            for auth in ["basic", "certificate", "negotiate", "ntlm", "negotiate", "kerberos", "credssp"]:
                if scheme == "http" and auth == "certificate":
                    continue

                host_name = f'{scheme}_{auth}_none_none'
                hosts[host_name] = {}
                self._add_to_groups(groups, host_name, [scheme, auth])

                for proxy_scheme in ["http", "https", "socks5", "socks5h"]:
                    proxy_group = f"proxy_{proxy_scheme}"
                    proxy_target_scheme_group = f"{scheme}_through_proxy"

                    host_name = f'{scheme}_{auth}_{proxy_scheme}_none'
                    hosts[host_name] = {}
                    self._add_to_groups(groups, host_name, [proxy_target_scheme_group, auth, proxy_group])

                    if proxy_scheme in ["socks5", "socks5h"]:
                        for socks in socks_info:
                            if socks["auth"] == "anon":
                                continue  # Done above

                            proxy_auth_group = f'{proxy_group}_{socks["auth"]}'
                            host_name = f'{scheme}_{auth}_{proxy_scheme}_{socks["auth"]}'
                            hosts[host_name] = {}
                            self._add_to_groups(groups, host_name, [proxy_target_scheme_group, auth, proxy_auth_group])

                    else:
                        for proxy in proxy_info:
                            if proxy["auth"] == "anon":
                                continue  # Done above

                            proxy_auth_group = f'{proxy_group}_{proxy["auth"]}'
                            host_name = f'{scheme}_{auth}_{proxy_scheme}_{proxy["auth"]}'
                            hosts[host_name] = {}
                            self._add_to_groups(groups, host_name, [proxy_target_scheme_group, auth, proxy_auth_group])

        result = {
            'windows': {
                'hosts': hosts,
                'vars': {
                    'ansible_host': target_host,
                    'ansible_connection': 'psrp',
                },
                'children': {}
            }
        }
        for group, group_info in groups.items():
            result['windows']['children'][group] = group_info

        return {
            'changed': False,
            'inventory': result,
        }

    def _add_to_groups(
        self,
        group_info: dict[str, dict[str, t.Any]],
        host: str,
        groups: list[str],
    ) -> None:
        for name in groups:
            group_info[name]['hosts'][host] = {}
