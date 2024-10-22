# frozen_string_literal: true

require_relative '../provider/keycloak_api'
require_relative '../../puppet_x/keycloak/type'
require_relative '../../puppet_x/keycloak/array_property'

Puppet::Type.newtype(:keycloak_identity_provider_mapper) do
  desc <<-DESC
Manage Keycloak Identity Provider mappers
@example Add first name SAML attribute mapping
  keycloak_identity_provider_mapper { 'first name for SAML on test:
    ensure                  => 'present',
    type                    => 'saml-user-attribute-idp-mapper',
    user_attribute          => 'firstName',
    attribute_friendly_name => 'givenName',
    attribute_name_format   => 'ATTRIBUTE_FORMAT_BASIC'
  }
  DESC

  extend PuppetX::Keycloak::Type
  add_autorequires

  ensurable

  newparam(:name, namevar: true) do
    desc 'The Identity Provider mapper name'
  end

  newparam(:id) do
    desc 'Id.'
  end

  newparam(:resource_name) do
    desc 'The Identity Provider mapper name. Defaults to `name`'
    defaultto do
      @resource[:name]
    end
  end

  newparam(:type) do
    desc 'identityProviderMapper'
    newvalues('saml-user-attribute-idp-mapper', 'hardcoded-attribute-idp-mapper')
    defaultto 'saml-user-attribute-idp-mapper'
    munge { |v| v }
  end

  newparam(:realm, namevar: true) do
    desc 'realm'
  end

  newparam(:identity_provider, namevar: true) do
    desc 'Name of parent `keycloak_identity_provider` resource'
  end

  newproperty(:sync_mode) do
    desc 'syncMode'
  end

  newproperty(:user_attribute) do
    desc 'user.attribute'
  end

  newproperty(:attribute_name) do
    desc 'attribute.name'
  end

  newproperty(:attribute_friendly_name) do
    desc 'attribute.friendly.name'
  end

  newproperty(:attribute_name_format) do
    desc 'attribute.name.format'
  end

  newproperty(:attribute_value) do
    desc 'attribute.value'
  end

  autorequire(:keycloak_identity_provider) do
    requires = []
    catalog.resources.each do |resource|
      next unless resource.instance_of?(Puppet::Type::Keycloak_identity_provider)

      if self[:identity_provider] == resource[:alias] && self[:realm] == resource[:realm]
        requires << resource.name
      end
    end
    requires
  end

  def self.title_patterns
    [
      [
        %r{^((.+) for (\S+) on (\S+))$},
        [
          [:name],
          [:resource_name],
          [:identity_provider],
          [:realm]
        ]
      ],
      [
        %r{(.*)},
        [
          [:name]
        ]
      ]
    ]
  end

  validate do
    required_properties = [
      :realm,
      :identity_provider
    ]
    required_properties.each do |property|
      if self[property].nil?
        raise Puppet::Error, "You must provide a value for #{property}"
      end
    end
    #    if self[:ensure] == :present
    #      if self[:type] == 'group-ldap-mapper' && self[:groups_dn].nil?
    #        raise Puppet::Error, 'Must define groups_dn for type group-ldap-mapper'
    #      end
    #
    #      if self[:type] == 'role-ldap-mapper'
    #        if self[:roles_dn].nil?
    #          raise Puppet::Error, 'Must define roles_dn for type role-ldap-mapper'
    #        end
    #        if self[:use_realm_roles_mapping].to_sym == :false && self[:client_id].nil?
    #          raise Puppet::Error, 'Must define client_id when user_realm_roles_mapping'
    #        end
    #      end
    #    end
  end
end
