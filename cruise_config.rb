# Project-specific configuration for CruiseControl.rb

Project.configure do |project|
  project.scheduler.polling_interval = 30.minutes
end
