# frozen_string_literal: true

# The gem is published as `nebula-token` but the library file is `nebula_token`,
# so `require 'nebula-token'` — the spelling Bundler's `gem 'nebula-token'` line
# suggests, and the one people reach for first — would otherwise raise LoadError.
# Both spellings load the same module.
require_relative 'nebula_token'
