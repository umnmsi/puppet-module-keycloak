# frozen_string_literal: true

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'keycloak_api'))

Puppet::Type.type(:keycloak_identity_provider_mapper).provide(:kcadm, parent: Puppet::Provider::KeycloakAPI) do
  desc ''

  mk_resource_methods

  def type_supported_properties(type)
    supported = {
      'saml-user-attribute-idp-mapper' => [
        :sync_mode, :user_attribute, :attribute_name, :attribute_friendly_name, :attribute_name_format
      ],
      'hardcoded-attribute-idp-mapper' => [
        :sync_mode, :attribute_value, :user_attribute
      ]
    }
    supported[type]
  end

  def self.instances
    mappers = []
    realms.each do |realm|
      identity_providers = []
      output = kcadm('get', 'identity-provider/instances', realm)
      Puppet.debug("#{realm} identity providers: #{output}")
      begin
        data = JSON.parse(output)
      rescue JSON::ParserError
        Puppet.debug('Unable to parse output from kcadm get identity-provider/instances')
        data = []
      end

      data.each do |d|
        identity_providers << d['alias']
      end

      identity_providers.each do |identity_provider|
        output = kcadm('get', "identity-provider/instances/#{identity_provider}/mappers", realm)
        Puppet.debug("#{realm} identity provider #{identity_provider} mappers: #{output}")
        begin
          data = JSON.parse(output)
        rescue JSON::ParserError
          Puppet.debug("Unable to parse output from kcadm get identity-provider/instances/#{identity_provider}/mappers")
          data = []
        end

        data.each do |d|
          next unless [
            'saml-user-attribute-idp-mapper', 'hardcoded-attribute-idp-mapper'
          ].include?(d['identityProviderMapper'])

          mapper = {}
          mapper[:ensure] = :present
          mapper[:id] = d['id']
          mapper[:realm] = realm
          mapper[:resource_name] = d['name']
          mapper[:type] = d['identityProviderMapper']
          mapper[:identity_provider] = d['identityProviderAlias']
          mapper[:name] = "#{mapper[:resource_name]} for #{mapper[:identity_provider]} on #{mapper[:realm]}"
          type_properties.each do |property|
            key = if property == :user_attribute && mapper[:type] == 'hardcoded-attribute-idp-mapper'
                    'attribute'
                  elsif property == :sync_mode
                    'syncMode'
                  else
                    property.to_s.tr('_', '.')
                  end
            unless d['config'].key?(key)
              mapper[property.to_sym] = :absent
              next
            end

            value = d['config'][key]
            if !!value == value # rubocop:disable Style/DoubleNegation
              value = value.to_s.to_sym
            end
            mapper[property.to_sym] = value
          end
          mappers << new(mapper)
        end
      end
    end
    mappers
  end

  def self.prefetch(resources)
    mappers = instances
    resources.each_key do |name|
      provider = mappers.find do |c|
        c.resource_name == resources[name][:resource_name] &&
          c.realm == resources[name][:realm] &&
          c.identity_provider == resources[name][:identity_provider]
      end
      next unless provider

      resources[name].provider = provider
    end
  end

  def create
    data = {}
    data[:id] = resource[:id] || name_uuid(resource[:name])
    data[:name] = resource[:resource_name]
    data[:identityProviderMapper] = resource[:type]
    data[:identityProviderAlias] = resource[:identity_provider]
    data[:config] = {}
    type_properties.each do |property|
      next unless resource[property.to_sym]
      next if resource[property.to_sym].to_s == 'absent'

      key = if property == :user_attribute && resource[:type] == 'hardcoded-attribute-idp-mapper'
              'attribute'
            elsif property == :sync_mode
              'syncMode'
            else
              property.to_s.tr('_', '.')
            end
      next unless type_supported_properties(resource[:type]).include?(property.to_sym)

      data[:config][key] = resource[property.to_sym]
    end

    t = Tempfile.new('keycloak_identity_provider_mapper')
    t.write(JSON.pretty_generate(data))
    t.close
    Puppet.debug(IO.read(t.path))
    begin
      kcadm('create', "identity-provider/instances/#{resource[:identity_provider]}/mappers", resource[:realm], t.path)
    rescue Puppet::ExecutionFailure => e
      raise Puppet::Error, "kcadm create identity-provider/instances/#{resource[:identity_provider]}/mappers failed\nError message: #{e.message}"
    end
    @property_hash[:ensure] = :present
  end

  def destroy
    begin
      kcadm('delete', "identity-provider/instances/#{resource[:identity_provider]}/mappers/#{id}", resource[:realm])
    rescue Puppet::ExecutionFailure => e
      raise Puppet::Error, "kcadm delete identity-provider/instances/#{resource[:identity_provider]}/mappers/#{id} failed\nError message: #{e.message}"
    end

    @property_hash.clear
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  type_properties.each do |prop|
    define_method "#{prop}=".to_sym do |value|
      @property_flush[prop] = value
    end
  end

  def flush
    unless @property_flush.empty?
      data = {}
      data[:id] = id
      data[:identityProviderAlias] = resource[:identity_provider]
      data[:identityProviderMapper] = resource[:type]
      data[:config] = {}
      type_properties.each do |property|
        key = if property == :user_attribute && resource[:type] == 'hardcoded-attribute-idp-mapper'
                'attribute'
              elsif property == :sync_mode
                'syncMode'
              else
                property.to_s.tr('_', '.')
              end
        next unless type_supported_properties(resource[:type]).include?(property.to_sym)

        value = resource[property.to_sym]
        if @property_flush[property.to_sym].to_s == 'absent'
          value = ''
        end
        data[:config][key] = value
      end

      t = Tempfile.new('keycloak_identity_provider_mapper')
      t.write(JSON.pretty_generate(data))
      t.close
      Puppet.debug(IO.read(t.path))
      begin
        kcadm('update', "identity-provider/instances/#{resource[:identity_provider]}/mappers/#{id}", resource[:realm], t.path)
      rescue Puppet::ExecutionFailure => e
        raise Puppet::Error, "kcadm update identity-provider/instances/#{resource[:identity_provider]}/mappers/#{id} failed\nError message: #{e.message}"
      end
    end
    # Collect the resources again once they've been changed (that way `puppet
    # resource` will show the correct values after changes have been made).
    @property_hash = resource.to_hash
  end
end
