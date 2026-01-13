# Acknowledgments

Authify builds upon the excellent work of the open-source community. We would like to acknowledge and thank the following projects and their contributors:

## ExScim

The SCIM 2.0 filter parser implementation in Authify is adapted from the [ExScim](https://github.com/ExScim/ex_scim) project:

- **Project**: ExScim
- **Repository**: https://github.com/ExScim/ex_scim
- **Copyright**: (c) 2025 wheredoipressnow
- **License**: MIT License

### Adapted Components

The following modules are based on ExScim's implementation:

- `Authify.SCIM.FilterParser` - Adapted from ExScim's filter parser
- `Authify.SCIM.Lexical` - Adapted from ExScim's lexical parsing helpers
- `Authify.SCIM.QueryFilter` - Adapted from ExScimEcto's query adapter

### Modifications

We've made the following modifications to better suit Authify's architecture and security requirements:

1. **Security Enhancement**: Replaced `String.to_atom/1` with allowlist-based attribute mapping (`Authify.SCIM.AttributeMapper`) to prevent atom table exhaustion attacks from untrusted SCIM filter expressions.

2. **Database Compatibility**: Modified query generation to use MySQL-compatible syntax (e.g., `like` instead of `ilike`).

3. **Integration**: Integrated the parser with Authify's Ecto-based data layer and multi-tenant architecture.

### Thank You

Special thanks to the ExScim project for their excellent SCIM filter parser implementation using NimbleParsec. Their work provided a solid foundation for Authify's SCIM 2.0 support.

---

## Other Acknowledgments

We also acknowledge the following dependencies and their contributors:

- **Phoenix Framework** - Modern web framework for Elixir
- **Ecto** - Database wrapper and language integrated query for Elixir
- **NimbleParsec** - Text-based parser combinator library
- **Guardian** - Authentication library for Elixir
- All other open-source dependencies listed in `mix.exs`

Thank you to the entire Elixir community for building amazing tools and libraries!
