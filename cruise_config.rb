# Project-specific configuration for CruiseControl.rb

Project.configure do |project|
  project.scheduler.polling_interval = 30.minutes
  #project.use_bundler = false
  #project.build_command = '/usr/local/bin/rbfu @2.0.0 ruby cruise_script.rb'
end
