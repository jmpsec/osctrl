# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

IP_ADDRESS = ENV["OSCTRL_IP_ADDRESS"] || "10.10.10.5"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/focal64"
  config.vm.network "private_network", ip: IP_ADDRESS
  # If we want to enroll nodes in the same network
  #config.vm.network "forwarded_port", guest: 443, host: 443
  config.vm.hostname = "osctrl-Dev"
  config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
  config.vm.provision "shell" do |s|
    s.path = "deploy/provision.sh"
    s.args = [
      "--nginx", "--postgres", "--redis", "--enroll", "--all-hostname",
      IP_ADDRESS, "--password", "admin"
    ]
    privileged = false
  end
  ["vmware_desktop", "virtualbox", "hyperv"].each do |provider|
    config.vm.provider provider do |v, override|
      v.memory = "1024"
      v.cpus = 1
    end
    config.vm.provider "virtualbox" do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    end
    config.vm.provider :vmware_desktop do |vmware|
      vmware.vmx["ethernet0.pcislotnumber"] = "32"
    end
  end
end
