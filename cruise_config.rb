# Project-specific configuration for CruiseControl.rb

Project.configure do |project|
  project.scheduler.polling_interval = 30.minutes
  project.review_changeset_url = 'https://github.com/mtgrosser/oo_auth/commit/%{changeset}'
end
