# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'nebula-token'
  spec.version       = '1.0.1'
  spec.authors       = ['Matteo Teodori']
  spec.email         = ['hello@nebulatoken.dev']
  spec.summary       = 'Opaque rotating refresh tokens (RFC 9700 model).'
  spec.description   = 'Rotation, reuse detection, family revocation, sender binding. Stdlib only.'
  spec.homepage      = 'https://nebulatoken.dev'
  # Singular: there is exactly one grant. `spec.licenses` (plural) would imply a
  # choice of terms that no longer exists.
  spec.license       = 'Apache-2.0'
  spec.required_ruby_version = '>= 3.3'
  # No runtime dependencies, by design: the library uses only openssl and
  # securerandom. In particular it does not use `base64`, which stopped being a
  # default gem in Ruby 3.4 — an undeclared require of it would raise LoadError
  # under Bundler and the gem would not load at all.
  #
  # An allow-list: both lib entry points, the docs and the licence file, and
  # deliberately no test/ — conformance is verified from a repository checkout
  # (RELEASING.md), not from the published gem.
  spec.files         = Dir['lib/**/*.rb', 'README.md',
                           'skills/nebula-token-ruby/SKILL.md', 'CHANGELOG.md',
                           'LICENSE']
  spec.require_paths = ['lib']
  spec.metadata      = {
    'homepage_uri' => 'https://nebulatoken.dev',
    'source_code_uri' => 'https://github.com/nebula-token/nebula-token/tree/main/packages/ruby',
    'changelog_uri' => 'https://github.com/nebula-token/nebula-token/blob/main/CHANGELOG.md',
    'bug_tracker_uri' => 'https://github.com/nebula-token/nebula-token/issues',
    'documentation_uri' => 'https://github.com/nebula-token/nebula-token/blob/main/SPECIFICATION.md',
    # RubyGems refuses a push from an account without MFA once this is set —
    # the gem cannot be taken over by a stolen password alone.
    'rubygems_mfa_required' => 'true'
  }
end
