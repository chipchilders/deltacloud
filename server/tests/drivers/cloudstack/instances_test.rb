require 'rubygems'
require 'require_relative' if RUBY_VERSION < '1.9'

require_relative 'common'

describe 'CloudStack Instances' do

  def credentials
  {
    :user => 'yy0sfCPpyKnvREhgpeIWzXORIIvyteq_iCgFpKXnqpdbnHuoYiK78nprSggG4hcx-hxwW897nU-XvGB0Tq8YFw',
    :password => 'Pse4fqYNnr1xvoRXlAe8NQKCSXeK_VGdwUxUzyLEPVQ7B3cI1Q7B8jmZ42FQpz2jIICFax1foIzg2716lJFZVw',
    :provider => 'http://192.168.56.10:8080/client/api/'
  }
  end

  before do
    @driver = Deltacloud::new(:cloudstack, credentials)
  end

  it 'must return list of instances' do
    @driver.instances.wont_be_empty
    @driver.instances.first.must_be_kind_of Instance
  end

end
