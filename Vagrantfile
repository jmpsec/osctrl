# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

IP_ADDRESS = "10.10.10.6"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.network "private_network", ip: IP_ADDRESS
  # If we want to enroll nodes in the same network
  #config.vm.network "forwarded_port", guest: 443, host: 443
  config.vm.hostname = "osctrl-Dev"
  config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
  config.vm.provision "shell" do |s|
    s.path = "deploy/provision.sh"
    s.args = [
      "--nginx", "--postgres", "-E", "--metrics", "--all-hostname",
      IP_ADDRESS, "--password", "admin"
    ]
    privileged = false
  end
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
    v.cpus = 1
    v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
  end
end
