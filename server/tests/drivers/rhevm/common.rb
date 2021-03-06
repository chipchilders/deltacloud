require 'vcr'

require_relative '../../test_helper'

# Credentials used to access RHEV-M server
#
# NOTE: If these are changed, the VCR fixtures need to be re-recorded
#
def credentials
  {
    :user => 'admin@internal',
    :password => 'redhat',
    :provider => 'https://dell-per610-02.lab.eng.brq.redhat.com/api;9df72b84-0234-11e2-9b87-9386d9b09d4a'
  }
end

VCR.configure do |c|
  # NOTE: Empty this directory before re-recording
  c.cassette_library_dir = File.join(File.dirname(__FILE__), 'fixtures')
  c.hook_into :webmock
  # Set this to :new_episodes when you want to 're-record'
  #c.default_cassette_options = { :record => :new_episodes }
  c.default_cassette_options = { :record => :none }
end
