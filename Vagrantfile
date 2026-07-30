Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"
  config.vbguest.auto_update = false
  config.vm.boot_timeout = 1800

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
  end
end