# WSMan Test Environment

Creates a test environment that we can use to test out the niche cases of WSMan.


## Requirements

* Vagrant
* QEMU/Libvirt
* Ansible


## Environment details

* DC01 - Domain controller
* APP - Windows host with fileshare for delegation testing
* TEST - WSMan endpoint exposed through proxy
* SQUID - Proxy host

The Squid proxy host needs to support both a http and socks proxy

* Authentication
  * Basic
  * Certificate
  * NTLM
  * Kerberos
  * CredSSP
* HTTPS listener with CA signed certificate(s)
  * Various sig algo types to test
* Proxy
  * No auth
  * Basic auth
  * Negotiate auth
  * Socks endpoint
* Credential delegation

