# Project-specific configuration for CruiseControl.rb

Project.configure do |project|
  project.scheduler.polling_interval = 30.minutes
  project.use_bundler = false
  project.build_command = 'rruby cruise_script.rb'
end
