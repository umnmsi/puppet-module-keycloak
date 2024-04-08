# frozen_string_literal: true

require_relative '../../puppet_x/keycloak/type'
require_relative '../../puppet_x/keycloak/array_property'
require_relative '../../puppet_x/keycloak/integer_property'

Puppet::Type.newtype(:keycloak_identity_provider) do
  desc <<-DESC
Manage Keycloak identity providers
@example Add CILogon identity provider to test realm
  keycloak_identity_provider { 'cilogon on test':
    ensure                         => 'present',
    display_name                   => 'CILogon',
    provider_id                    => 'oidc',
    first_broker_login_flow_alias  => 'browser',
    client_id                      => 'cilogon:/client_id/foobar',
    client_secret                  => 'supersecret',
    user_info_url                  => 'https://cilogon.org/oauth2/userinfo',
    token_url                      => 'https://cilogon.org/oauth2/token',
    authorization_url              => 'https://cilogon.org/authorize',
  }
  DESC

  # Provider-specific properties
  def property_map
    {
      # OIDC
      user_info_url: ['oidc', 'keycloak-oidc'],
      client_id: ['oidc', 'keycloak-oidc'],
      client_secret: ['oidc', 'keycloak-oidc'],
      client_auth_method: ['oidc', 'keycloak-oidc'],
      token_url: ['oidc', 'keycloak-oidc'],
      ui_locales: ['oidc', 'keycloak-oidc'],
      use_jwks_url: ['oidc', 'keycloak-oidc'],
      jwks_url: ['oidc', 'keycloak-oidc'],
      authorization_url: ['oidc', 'keycloak-oidc'],
      disable_user_info: ['oidc', 'keycloak-oidc'],
      logout_url: ['oidc', 'keycloak-oidc'],
      issuer: ['oidc', 'keycloak-oidc'],
      default_scope: ['oidc', 'keycloak-oidc'],
      prompt: ['oidc', 'keycloak-oidc'],
      allowed_clock_skew: ['oidc', 'keycloak-oidc'],
      forward_parameters: ['oidc', 'keycloak-oidc'],
      # SAML
      post_binding_logout: ['saml'],
      post_binding_response: ['saml'],
      idp_entity_id: ['saml'],
      allow_create: ['saml'],
      enabled_from_metadata: ['saml'],
      authn_context_comparison_type: ['saml'],
      single_sign_on_service_url: ['saml'],
      want_authn_requests_signed: ['saml'],
      encryption_public_key: ['saml'],
      signing_certificate: ['saml'],
      name_i_d_policy_format: ['saml'],
      principal_attribute: ['saml'],
      entity_id: ['saml'],
      sign_sp_metadata: ['saml'],
      want_assertions_encrypted: ['saml'],
      send_client_id_on_logout: ['saml'],
      want_assertions_signed: ['saml'],
      metadata_descriptor_url: ['saml'],
      send_id_token_on_logout: ['saml'],
      post_binding_authn_request: ['saml'],
      force_authn: ['saml'],
      attribute_consuming_service_index: ['saml'],
      add_extensions_element_with_key_info: ['saml'],
      principal_type: ['saml'],
    }
  end

  extend PuppetX::Keycloak::Type
  add_autorequires

  ensurable

  newparam(:name, namevar: true) do
    desc 'The identity provider name'
  end

  newparam(:alias, namevar: true) do
    desc 'The identity provider name. Defaults to `name`.'
    defaultto do
      @resource[:name]
    end
  end

  newparam(:internal_id) do
    desc 'internalId. Defaults to "`alias`-`realm`"'
    defaultto do
      "#{@resource[:alias]}-#{@resource[:realm]}"
    end
  end

  newparam(:realm, namevar: true) do
    desc 'realm'
  end

  newproperty(:display_name) do
    desc 'displayName'
  end

  newparam(:provider_id) do
    desc 'providerId'
    newvalues('oidc', 'keycloak-oidc', 'saml')
    defaultto 'oidc'
    munge { |v| v }
  end

  newproperty(:enabled, boolean: true) do
    desc 'enabled'
    newvalues(:true, :false)
    defaultto :true
  end

  newproperty(:update_profile_first_login_mode) do
    desc 'updateProfileFirstLoginMode'
    defaultto 'on'
    newvalues('on', 'off')
    munge { |v| v }
  end

  newproperty(:trust_email, boolean: true) do
    desc 'trustEmail'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:store_token, boolean: true) do
    desc 'storeToken'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:add_read_token_role_on_create, boolean: true) do
    desc 'addReadTokenRoleOnCreate'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:authenticate_by_default, boolean: true) do
    desc 'authenticateByDefault'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:link_only, boolean: true) do
    desc 'linkOnly'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:gui_order, parent: PuppetX::Keycloak::IntegerProperty) do
    desc 'guiOrder'
    munge { |v| v.to_s }
  end

  newproperty(:first_broker_login_flow_alias) do
    desc 'firstBrokerLoginFlowAlias'
    defaultto 'first broker login'
    munge { |v| v }
  end

  newproperty(:post_broker_login_flow_alias) do
    desc 'postBrokerLoginFlowAlias'
    munge { |v| v }
  end

  newproperty(:sync_mode) do
    desc 'syncMode'
    defaultto 'IMPORT'
    newvalues('IMPORT', 'LEGACY', 'FORCE')
    munge { |v| v }
  end

  newproperty(:hide_on_login_page, boolean: true) do
    desc 'hideOnLoginPage'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:login_hint, boolean: true) do
    desc 'loginHint'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:backchannel_supported, boolean: true) do
    desc 'backchannelSupported'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:allowed_clock_skew) do
    desc 'allowedClockSkew'
  end

  newproperty(:validate_signature, boolean: true) do
    desc 'validateSignature'
    newvalues(:true, :false)
    defaultto :false
  end

  # BEGIN: oidc

  newproperty(:user_info_url) do
    desc 'userInfoUrl'
    munge { |v| v }
  end

  newproperty(:client_id) do
    desc 'clientId'
  end

  newproperty(:client_secret) do
    desc 'clientSecret'

    def insync?(is)
      if is =~ %r{^\*+$}
        Puppet.warning("Parameter 'client_secret' is set and Puppet has no way to check current value")
        true
      else
        false
      end
    end

    def change_to_s(currentvalue, _newvalue)
      if currentvalue == :absent
        'created client_secret'
      else
        'changed client_secret'
      end
    end

    def is_to_s(_currentvalue) # rubocop:disable Style/PredicateName
      '[old client_secret redacted]'
    end

    def should_to_s(_newvalue)
      '[new client_secret redacted]'
    end
  end

  newproperty(:client_auth_method) do
    desc 'clientAuthMethod'
    newvalues('client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt')
    defaultto('client_secret_post')
    munge { |v| v.to_s }
  end

  newproperty(:token_url) do
    desc 'tokenUrl'
  end

  newproperty(:ui_locales, boolean: true) do
    desc 'uiLocales'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:use_jwks_url, boolean: true) do
    desc 'useJwksUrl'
    newvalues(:true, :false)
    defaultto :true
  end

  newproperty(:jwks_url) do
    desc 'jwksUrl'
    munge { |v| v }
  end

  newproperty(:authorization_url) do
    desc 'authorizationUrl'
  end

  newproperty(:disable_user_info, boolean: true) do
    desc 'disableUserInfo'
    newvalues(:true, :false)
    defaultto :false
  end

  newproperty(:logout_url) do
    desc 'logoutUrl'
  end

  newproperty(:issuer) do
    desc 'issuer'
  end

  newproperty(:default_scope) do
    desc 'default_scope'
  end

  newproperty(:prompt) do
    desc 'prompt'
    newvalues('none', 'consent', 'login', 'select_account')
    munge { |v| v }
  end

  newproperty(:forward_parameters) do
    desc 'forwardParameters'
  end

  # END: oidc

  # BEGIN: saml

  newproperty(:post_binding_logout) do
    desc 'postBindingLogout'
    newvalues(:true, :false)
  end

  newproperty(:post_binding_response) do
    desc 'postBindingResponse'
    newvalues(:true, :false)
  end

  newproperty(:idp_entity_id) do
    desc 'idpEntityId'
  end

  newproperty(:allow_create) do
    desc 'allowCreate'
    newvalues(:true, :false)
  end

  newproperty(:enabled_from_metadata) do
    desc 'enabledFromMetadata'
    newvalues(:true, :false)
  end

  newproperty(:authn_context_comparison_type) do
    desc 'authnContextComparisonType'
    newvalues('exact', 'minimum', 'maximum', 'better')
  end

  newproperty(:single_sign_on_service_url) do
    desc 'singleSignOnServiceUrl'
  end

  newproperty(:want_authn_requests_signed) do
    desc 'wantAuthnRequestsSigned'
    newvalues(:true, :false)
  end

  newproperty(:encryption_public_key) do
    desc 'encryptionPublicKey'
  end

  newproperty(:signing_certificate) do
    desc 'signingCertificate'
  end

  newproperty(:name_i_d_policy_format) do
    desc 'nameIDPolicyFormat'
  end

  newproperty(:principal_attribute) do
    desc 'principalAttribute'
  end

  newproperty(:entity_id) do
    desc 'entityId'
  end

  newproperty(:sign_sp_metadata) do
    desc 'signSpMetadata'
    newvalues(:true, :false)
  end

  newproperty(:want_assertions_encrypted) do
    desc 'wantAssertionsEncrypted'
    newvalues(:true, :false)
  end

  newproperty(:send_client_id_on_logout) do
    desc 'sendClientIdOnLogout'
    newvalues(:true, :false)
  end

  newproperty(:want_assertions_signed) do
    desc 'wantAssertionsSigned'
    newvalues(:true, :false)
  end

  newproperty(:metadata_descriptor_url) do
    desc 'metadataDescriptorUrl'
  end

  newproperty(:send_id_token_on_logout) do
    desc 'sendIdTokenOnLogout'
    newvalues(:true, :false)
  end

  newproperty(:post_binding_authn_request) do
    desc 'postBindingAuthnRequest'
    newvalues(:true, :false)
  end

  newproperty(:force_authn) do
    desc 'forceAuthn'
    newvalues(:true, :false)
  end

  newproperty(:attribute_consuming_service_index) do
    desc 'attributeConsumingServiceIndex'
  end

  newproperty(:add_extensions_element_with_key_info) do
    desc 'addExtensionsElementWithKeyInfo'
    newvalues(:true, :false)
  end

  newproperty(:principal_type) do
    desc 'principal_type'
    newvalues('ATTRIBUTE', 'FRIENDLY_ATTRIBUTE', 'SUBJECT')
  end

  # END: saml

  def self.title_patterns
    [
      [
        %r{^((\S+) on (\S+))$},
        [
          [:name],
          [:alias],
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
    if self[:realm].nil?
      raise Puppet::Error, 'realm is required'
    end

    if self[:ensure].to_s == 'present' && ['oidc', 'keycloak-oidc'].include?(self[:provider_id])
      if self[:authorization_url].nil?
        raise Puppet::Error, 'authorization_url is required'
      end
      if self[:token_url].nil?
        raise Puppet::Error, 'token_url is required'
      end
      if self[:client_id].nil?
        raise Puppet::Error, 'client_id is required'
      end
      if self[:client_secret].nil?
        raise Puppet::Error, 'client_secret is required'
      end
    end
    parameters.each do |parameter, obj|
      # Remove default values for alternate providers
      @parameters.delete(parameter) if property_map.key?(parameter.to_sym) && !property_map[parameter.to_sym].include?(self[:provider_id])
    end
  end

  autorequire(:keycloak_flow) do
    requires = []
    catalog.resources.each do |resource|
      next unless resource.instance_of?(Puppet::Type::Keycloak_flow)
      next if self[:realm] != resource[:realm]

      if self[:first_broker_login_flow_alias] == resource[:alias]
        requires << resource.name
      end
      if self[:post_broker_login_flow_alias] == resource[:alias]
        requires << resource.name
      end
    end
    requires
  end
end
