#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.

require 'cloudstack_ruby_client'
require 'yaml'
require 'base64'
require 'etc'
require 'ipaddr'

require_relative 'cloudstack_driver_cimi_methods'
require_relative '../../runner'

module Deltacloud::Drivers::Cloudstack

  class CloudstackDriver < Deltacloud::BaseDriver

    ( REALMS = [
      Realm.new({
        :id=>'csdefault',
        :name=>'Default CloudStack Region',
        :limit=>:unlimited,
        :state=>'AVAILABLE'}),
      ] ) unless defined?( REALMS )

    # Some clouds tell us nothing about hardware profiles (e.g., OpenNebula)
    define_hardware_profile 'opaque'

    define_instance_states do
      start.to( :pending )       .on( :create )

      pending.to( :running )     .automatically

      running.to( :running )     .on( :reboot )
      running.to( :stopped )     .on( :stop )

      stopped.to( :running )     .on( :start )
      stopped.to( :finish )      .on( :destroy )
    end

    feature :instances, :user_name
    feature :instances, :user_data
    feature :instances, :authentication_key
    feature :instances, :metrics
    feature :instances, :realm_filter
    feature :images, :user_name
    feature :images, :user_description

    #cimi features
    feature :machines, :default_initial_state do
      { :values => ["STARTED"] }
    end
    feature :machines, :initial_states do
      { :values => ["STARTED", "STOPPED"]}
    end


    def realms(credentials, opts={})
      client = new_client( credentials )
      results = []
      safely do
        # This hack is used to test if client capture exceptions correctly
        # To raise an exception do GET /api/realms/50[0-2]
        raise "DeltacloudErrorTest" if opts and opts[:id] == "500"
        raise "NotImplementedTest" if opts and opts[:id] == "501"
        raise "ProviderErrorTest" if opts and opts[:id] == "502"
        raise "ProviderTimeoutTest" if opts and opts[:id] == "504"
        results = REALMS
      end
      results = filter_on( results, :id, opts )
      results
    end

    #
    # Images
    #
    def images(credentials, opts=nil )
      client = new_client( credentials )
      images = []
      images = client.build_all(Image)
      images = filter_on( images, :id, opts )
      images = filter_on( images, :architecture, opts )
      if ( opts && opts[:owner_id] == 'self' )
        images = images.select{|e| e.owner_id == credentials.user }
      else
        images = filter_on( images, :owner_id, opts )
      end
      images = images.map { |i| (i.hardware_profiles = hardware_profiles(nil)) && i }
      images.sort_by{|e| [e.owner_id, e.description]}
    end

    def create_image(credentials, opts={})
      client = new_client(credentials)
      instance = instance(credentials, :id => opts[:id])
      safely do
        raise 'CreateImageNotSupported' unless instance and instance.can_create_image?
        image = {
          :id => opts[:name],
          :name => opts[:name],
          :owner_id => 'root',
          :state => "AVAILABLE",
          :description => opts[:description],
          :architecture => 'i386'
        }
        client.store(:images, image)
        Image.new(image)
      end
    end

    def destroy_image(credentials, id)
      client = new_client( credentials )
      client.destroy(:images, id)
    end

    #
    # Instances
    #

    def instance(credentials, opts={})
      client = new_client( credentials )
      safely do
        client.listVirtualMachines()
      end
    end

    def instances(credentials, opts={})
      client = new_client( credentials )
      instances = convert_from_vms(client.listVirtualMachines())
      instances
    end

    def create_instance(credentials, image_id, opts)
      client = new_client( credentials )
      ids = client.members(:instances)

      count = 0
      while true
        next_id = "inst" + count.to_s
        if not ids.include?(next_id)
          break
        end
        count = count + 1
      end

      realm_id = opts[:realm_id]
      if ( realm_id.nil? )
        realm = realms(credentials).first
        ( realm_id = realm.id ) if realm
      end

      hwp = find_hardware_profile(credentials, opts[:hwp_id], image_id)
      hwp ||= find_hardware_profile(credentials, 'm1-small', image_id)

      name = opts[:name] || "i-#{Time.now.to_i}"

      instance = {
        :id => next_id,
        :name=>name,
        :state=>'RUNNING',
        :keyname => opts[:keyname],
        :image_id=>image_id,
        :owner_id=>credentials.user,
        :public_addresses=>[ InstanceAddress.new("#{image_id}.#{next_id}.public.com", :type => :hostname) ],
        :private_addresses=>[ InstanceAddress.new("#{image_id}.#{next_id}.private.com", :type => :hostname) ],
        :instance_profile => InstanceProfile.new(hwp.name, opts),
        :realm_id=>realm_id,
        :create_image=>true,
        :actions=>instance_actions_for( 'RUNNING' ),
        :user_data => opts[:user_data] ? Base64::decode64(opts[:user_data]) : nil
      }
      client.store(:instances, instance)
      Instance.new( instance )
    end

    def update_instance_state(credentials, id, state)
      instance  = client.load_collection(:instances, id)
      instance[:state] = state
      instance[:actions] = instance_actions_for( instance[:state] )
      client.store(:instances, instance)
      Instance.new( instance )
    end

    def start_instance(credentials, id)
      update_instance_state(credentials, id, 'RUNNING')
    end

    def reboot_instance(credentials, id)
      update_instance_state(credentials, id, 'RUNNING')
    end

    def stop_instance(credentials, id)
      update_instance_state(credentials, id, 'STOPPED')
    end


    def destroy_instance(credentials, id)
      client = new_client( credentials )
      client.destroy(:instances, id)
    end

    # mock object to mimick Net::SSH object
    class Mock_ssh
      attr_accessor :command
    end

    def run_on_instance(credentials, opts={})
      ssh = Mock_ssh.new
      ssh.command = opts[:cmd]
      Deltacloud::Runner::Response.new(ssh, "This is where the output would appear if this were not a mock provider")
    end

    #
    # Storage Volumes
    #
    def storage_volumes(credentials, opts=nil)
      client = new_client( credentials )
      volumes = client.build_all(StorageVolume)
      volumes = filter_on( volumes, :id, opts )
      volumes
    end

    def create_storage_volume(credentials, opts={})
      client = new_client(credentials)
      opts[:capacity] ||= "1"
      id = "Volume#{Time.now.to_i}"
      volume = {
            :id => id,
            :name => opts[:name] ? opts[:name] : id,
            :created => Time.now.to_s,
            :state => "AVAILABLE",
            :capacity => opts[:capacity],
      }
      client.store(:storage_volumes, volume)
      StorageVolume.new(volume)
    end

    def destroy_storage_volume(credentials, opts={})
      client = new_client(credentials)
      client.destroy(:storage_volumes, opts[:id])
    end

    #opts: {:id=,:instance_id,:device}
    def attach_storage_volume(credentials, opts={})
      client = new_client(credentials)
      attach_volume_instance(opts[:id], opts[:device], opts[:instance_id])
    end

    def detach_storage_volume(credentials, opts)
      client = new_client(credentials)
      detach_volume_instance(opts[:id], opts[:instance_id])
    end

    #
    # Storage Snapshots
    #

    def storage_snapshots(credentials, opts=nil)
      client = new_client( credentials )
      snapshots = client.build_all(StorageSnapshot)
      snapshots = filter_on(snapshots, :id, opts )
      snapshots
    end

    def create_storage_snapshot(credentials, opts={})
      client = new_client(credentials)
      id = "store_snapshot_#{Time.now.to_i}"
      snapshot = {
            :id => id,
            :created => Time.now.to_s,
            :state => "COMPLETED",
            :storage_volume_id => opts[:volume_id],
      }
      snapshot.merge!({:name=>opts[:name]}) if opts[:name]
      snapshot.merge!({:description=>opts[:description]}) if opts[:description]
      client.store(:storage_snapshots, snapshot)
      StorageSnapshot.new(snapshot)
    end

    def destroy_storage_snapshot(credentials, opts={})
      client = new_client(credentials)
      client.destroy(:storage_snapshots, opts[:id])
    end

    def keys(credentials, opts={})
      client = new_client(credentials)
      result = client.build_all(Key)
      result = filter_on( result, :id, opts )
      result
    end

    def key(credentials, opts={})
      keys(credentials, opts).first
    end

    def create_key(credentials, opts={})
      client = new_client(credentials)
      key_hash = {
        :id => opts[:key_name],
        :credential_type => :key,
        :fingerprint => Key::generate_mock_fingerprint,
        :pem_rsa_key => Key::generate_mock_pem
      }
      safely do
        raise "KeyExist" if client.load_collection(:keys, key_hash[:id])
        client.store(:keys, key_hash)
      end
      return Key.new(key_hash)
    end

    def destroy_key(credentials, opts={})
      key = key(credentials, opts)
      client.destroy(:keys, key.id)
    end

    def addresses(credentials, opts={})
      client = new_client(credentials)
      addresses = client.build_all(Address)
      addresses = filter_on( addresses, :id, opts )
    end

    def create_address(credentials, opts={})
      client = new_client(credentials)
      address = {:id => allocate_mock_address.to_s, :instance_id=>nil}
      client.store(:addresses, address)
      Address.new(address)
    end

    def destroy_address(credentials, opts={})
      client = new_client(credentials)
      address = client.load_collection(:addresses, opts[:id])
      raise "AddressInUse" unless address[:instance_id].nil?
      client.destroy(:addresses, opts[:id])
    end

    def associate_address(credentials, opts={})
      client = new_client(credentials)
      address = client.load_collection(:addresses, opts[:id])
      raise "AddressInUse" unless address[:instance_id].nil?
      instance = client.load_collection(:instances, opts[:instance_id])
      address[:instance_id] = instance[:id]
      instance[:public_addresses] = [InstanceAddress.new(address[:id])]
      client.store(:addresses, address)
      client.store(:instances, instance)
    end

    def disassociate_address(credentials, opts={})
      client = new_client(credentials)
      address = client.load_collection(:addresses, opts[:id])
      raise "AddressNotInUse" unless address[:instance_id]
      instance = client.load_collection(:instances, address[:instance_id])
      address[:instance_id] = nil
      instance[:public_addresses] = [InstanceAddress.new("#{instance[:image_id]}.#{instance[:id]}.public.com", :type => :hostname)]
      client.store(:addresses, address)
      client.store(:instances, instance)
    end

    #--
    # Metrics
    #--
    def metrics(credentials, opts={})
      client = new_client( credentials )
      instances = client.build_all(Instance)
      instances = filter_on( instances, :id, opts )

      metrics_arr = instances.collect do |instance|
        Metric.new(
          :id     => instance.id,
          :entity => instance.name
        )
      end

      # add metric names to metrics
      metrics_arr.each do |metric|
        @@METRIC_NAMES.each do |name|
          metric.add_property(name)
        end
        metric.properties.sort! {|a,b| a.name <=> b.name}
      end
      metrics_arr
    end

    def metric(credentials, opts={})
      metric = metrics(credentials, opts).first

      metric.properties.each do |property|

        property.values = (0..5).collect do |i|

          unit = metric_unit_for(property.name)
          average = (property.name == 'cpuUtilization') ? (rand * 1000).to_i / 10.0 : rand(1000)
          max = (property.name == 'cpuUtilization') ? (1000 + 10 * average).to_i / 20.0 : average * (i + 1)
          min = (property.name == 'cpuUtilization') ? (2.5 * average).to_i / 10.0 : (average / 4).to_i
          {
            :minimum   => min,
            :maximum   => max,
            :average   => average,
            :timestamp => Time.now - i * 60,
            :unit      => unit
          }
        end
      end
      metric
    end

    def valid_credentials?(credentials)
      begin
        new_client(credentials)
        return true
      rescue
      end
      return false
    end

    private

    def new_client(credentials)
      safely do
        if credentials.user.empty?
          raise AuthenticationFailure.new(Exception.new("Error: you must supply your CloudStack API key as your username"))
        end
        if credentials.password.empty?
          raise AuthenticationFailure.new(Exception.new("Error: you must supply your CloudStack Secret key as your password"))
        end
        #if credentials.provider.empty?
        #  raise AuthenticationFailure.new(Exception.new("Error: you must supply the API endpoint URL as the provider"))
        #end
        puts credentials.to_s
        # HACK: I actually need to fix the client gem to remove the last init param
        return CloudstackRubyClient::Client.new(credentials.provider, credentials.user, credentials.password, false)
      end
    end

    #Mock allocation of 'new' address
    #There is a synchronization problem (but it's the mock driver,
    #mutex seemed overkill)
    def allocate_mock_address
      addresses = []
      client.members(:addresses).each do |addr|
        addresses << IPAddr.new("#{addr}").to_i
      end
      IPAddr.new(addresses.sort.pop+1, Socket::AF_INET)
    end

    def attach_volume_instance(volume_id, device, instance_id)
      volume = client.load_collection(:storage_volumes, volume_id)
      instance = client.load_collection(:instances, instance_id)
      volume[:instance_id] = instance_id
      volume[:device] = device
      volume[:state] = "IN-USE"
      instance[:storage_volumes] ||= []
      instance[:storage_volumes] << {volume_id=>device}
      client.store(:storage_volumes, volume)
      client.store(:instances, instance)
      StorageVolume.new(volume)
    end

    def detach_volume_instance(volume_id, instance_id)
      volume = client.load_collection(:storage_volumes, volume_id)
      instance = client.load_collection(:instances, instance_id)
      volume[:instance_id] = nil
      device = volume[:device]
      volume[:device] = nil
      volume[:state] = "AVAILABLE"
      instance[:storage_volumes].delete({volume_id => device}) unless instance[:storage_volumes].nil?
      client.store(:storage_volumes, volume)
      client.store(:instances, instance)
      StorageVolume.new(volume)
    end

    def metric_unit_for(name)
      case name
        when /Utilization/ then 'Percent'
        when /Byte/ then 'Bytes'
        when /Sector/ then 'Count'
        when /Count/ then 'Count'
        when /Packet/ then 'Count'
        else 'None'
      end
    end

    # Conversion methods

    def convert_from_vm(vm)
      inst = Instance.new(
        :id => vm.id,
        :realm_id => 'default',
        :owner_id => vm.account,
        :description => vm.name,
        :state => :running, #convert_vm_state(vm.state),
        :architecture => 'x86_64',
        :image_id => vm.templateid,
        :instance_profile => InstanceProfile::new(vm.serviceofferingid),
        :public_addresses => InstanceAddress.new('', :public ), #convert_vm_addresses(vm, :public),
        :private_addresses => InstanceAddress.new('', :private ),#convert_vm_addresses(vm, :private),
        :username => 'root',
        :password => vm.password,
        :keyname => vm.keypair
      )
      inst
    end



    # names copied from FGCP driver
    @@METRIC_NAMES = [
      'cpuUtilization',
      'diskReadRequestCount',
      'diskReadSector',
      'diskWriteRequestCount',
      'diskWriteSector',
      'nicInputByte',
      'nicInputPacket',
      'nicOutputByte',
      'nicOutputPacket'
    ]

    exceptions do

      on /AuthFailure/ do
        status 401
        message "Authentication Failure"
      end

      on /BucketNotEmpty/ do
        status 403
        message "Delete operation not valid for non-empty bucket"
      end

      on /KeyExist/ do
        status 403
        message "Key with same name already exists"
      end

      on /AddressInUse/ do
        status 403
      end

      on /AddressNotInUse/ do
        status 403
      end

      on /BucketNotExist/ do
        status 404
      end

      on /CreateImageNotSupported/ do
        status 500
      end

      on /NotExistentBlob/ do
        status 500
        message "Could not delete a non existent blob"
      end

      on /DeltacloudErrorTest/ do
        status 500
        message "DeltacloudErrorMessage"
      end

      on /NotImplementedTest/ do
        status 501
        message "NotImplementedMessage"
      end

      on /ProviderErrorTest/ do
        status 502
        message "ProviderErrorMessage"
      end

      on /ProviderTimeoutTest/ do
        status 504
        message "ProviderTimeoutMessage"
      end

    end

  end

end
