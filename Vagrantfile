# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.network "private_network", ip: "10.10.10.6"
  config.vm.network "forwarded_port", guest: 443, host: 443
  config.vm.hostname = "osctrl-Dev"
  config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
  config.vm.provision "shell" do |s|
    s.path = "deploy/provision.sh"
    s.args = ["--nginx", "--postgres", "-p", "all", "--tls-hostname", "10.10.10.6", "--admin-hostname", "10.10.10.6"]
    privileged = false
  end
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
    v.cpus = 1
    v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
  end
end
