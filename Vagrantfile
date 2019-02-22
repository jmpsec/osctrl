# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

targets = {
  "ubuntu" => {
    "box" => "ubuntu/bionic64"
  },
  "centos" => {
    "box" => "centos/7"
  },
}

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
    v.cpus = 1
    v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
  end
  targets.each do |name, target|
    box = target["box"]
    config.vm.define name do |build|
      build.vm.box = box
      build.vm.network "private_network", ip: "10.10.10.6"
      build.vm.network "forwarded_port", guest: 443, host: 443
      build.vm.hostname = "osctrl-Dev"
      build.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
      build.vm.provision "shell" do |s|
        s.path = "deploy/provision.sh"
        s.args = ["--nginx", "--postgres", "-p", "all", "--tls-hostname", "10.10.10.6", "--admin-hostname", "10.10.10.6"]
        privileged = false
      end
    end
  end
end
