# -*- mode: ruby -*-
# vi: set ft=ruby :

require 'yaml'

inventory = YAML.load_file('inventory.yml')

Vagrant.configure("2") do |config|
  inventory['all']['children'].each do |group,details|
    details['hosts'].each do |server,host_details|
      config.vm.define server do |srv|
        srv.vm.box = host_details['vagrant_box']
        srv.vm.hostname = server
        srv.vm.network :private_network,
          :ip => host_details['ansible_host'],
          :libvirt__network_name => 'winrm-test',
          :libvirt__domain_name => inventory['all']['vars']['domain_realm']

        srv.vm.provider :libvirt do |l|
          l.memory = 4096
          l.cpus = 2
        end

        if group == 'linux' then
          srv.vm.provision 'shell', inline: <<-SHELL
           sed -re 's/^(PasswordAuthentication)([[:space:]]+)no/\\1\\2yes/' -i /etc/ssh/sshd_config
           systemctl restart sshd
         SHELL
        end
      end
    end
  end
end

