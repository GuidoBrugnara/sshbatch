package Auth_AC::AuthCookieHandler;

use strict;
use warnings;

use Apache2::AuthCookie;
use Apache2::Cookie;
use Apache2::RequestRec ();
use Apache2::Const -compile => qw(HTTP_FORBIDDEN OK REDIRECT);

use base qw(Apache2::AuthCookie);

=head1 NAME

Auth_AC::AuthCookieHandler - Handler di autenticazione basato su cookie per Apache2

=head1 SYNOPSIS

    # In httpd.conf o virtual host config:
    PerlModule Auth_AC::AuthCookieHandler
    
    PerlSetVar MyAuthPath /
    PerlSetVar MyAuthLoginScript /login.pl
    PerlSetVar MyAuthCookieName MySessionCookie
    PerlSetVar MyAuthExpires +1h
    
    <Location /protected>
        AuthType Auth_AC::AuthCookieHandler
        AuthName MyAuth
        PerlAuthenHandler Auth_AC::AuthCookieHandler->authenticate
        PerlAuthzHandler Auth_AC::AuthCookieHandler->authorize
        Require valid-user
    </Location>

=head1 DESCRIPTION

Questo modulo implementa un handler di autenticazione basato su cookie
che cancella il cookie di sessione e restituisce HTTP 403 quando la
sessione non è valida.

=cut

use constant COOKIE_NAME => 'mellon-cookie';

# Validate session key and return username or undef
sub authen_ses_key {
    my ($self, $r, $session_key) = @_;
    
    # Fetch all cookies from request
    my %cookies = Apache2::Cookie->fetch($r);
    
    # Get mellon-cookie value
    my $mellon_cookie = $cookies{COOKIE_NAME()};
    my $cookie_value = $mellon_cookie ? $mellon_cookie->value : undef;
    
    # Validate session (replace with your validation logic)
    my $user = $self->_validate_session($r, $cookie_value || $session_key);
    
    unless ($user) {
        # Session invalid: delete mellon-cookie from browser
        $self->_expire_cookie($r, COOKIE_NAME);
        
        # Set custom error note to signal 403 should be returned
        $r->notes->set('AuthCookieReason' => 'SessionExpired');
        
        # Log the event
        $r->log->warn("Session invalid or expired, deleting cookie: " . COOKIE_NAME);
        
        return undef;
    }
    
    return $user;
}

# Expire/delete the cookie by setting expiration in the past
sub _expire_cookie {
    my ($self, $r, $cookie_name) = @_;
    
    $cookie_name ||= COOKIE_NAME;
    
    my $path = $r->dir_config('MellonCookiePath') || '/';
    my $domain = $r->dir_config('MellonCookieDomain');
    
    # Create expired cookie to delete from browser
    # Setting expires to a past date tells browser to remove it
    my $expired_cookie = Apache2::Cookie->new($r,
        -name    => $cookie_name,
        -value   => '',
        -expires => '-1d',      # Expired 1 day ago
        -path    => $path,
        ($domain ? (-domain => $domain) : ()),
    );
    
    # bake() adds Set-Cookie header to response
    $expired_cookie->bake($r);
    
    $r->log->debug("Cookie '$cookie_name' marked for deletion (Set-Cookie with expires in past)");
    
    return;
}

# Override authenticate to handle 403 response
sub authenticate {
    my ($self, $r) = @_;
    
    # Call parent authenticate method
    my $result = $self->SUPER::authenticate($r);
    
    # Check if we should return 403 instead of redirect
    if ($r->notes->get('AuthCookieReason') && 
        $r->notes->get('AuthCookieReason') eq 'SessionExpired') {
        
        # Clear the note
        $r->notes->unset('AuthCookieReason');
        
        # Return HTTP 403 Forbidden
        $r->log->info("Returning HTTP 403 for expired session");
        return Apache2::Const::HTTP_FORBIDDEN;
    }
    
    return $result;
}

# Session validation logic (customize this)
sub _validate_session {
    my ($self, $r, $session_key) = @_;
    
    return unless $session_key;
    
    # Example: decode and validate session
    # Replace this with your actual session validation
    # e.g., database lookup, Redis check, JWT validation, etc.
    
    # Simple example: session format "username:timestamp:signature"
    my ($username, $timestamp, $signature) = split /:/, $session_key, 3;
    
    return unless $username && $timestamp && $signature;
    
    # Check if session has expired (example: 1 hour timeout)
    my $session_timeout = $r->dir_config('MyAuthSessionTimeout') || 3600;
    if (time() - $timestamp > $session_timeout) {
        $r->log->debug("Session expired for user: $username");
        return;
    }
    
    # Validate signature (implement your signature verification)
    # unless ($self->_verify_signature($username, $timestamp, $signature)) {
    #     return;
    # }
    
    return $username;
}

# Authorization handler
sub authorize {
    my ($self, $r) = @_;
    
    my $user = $r->user;
    return Apache2::Const::HTTP_FORBIDDEN unless $user;
    
    # Add your authorization logic here
    # e.g., check user roles, permissions, etc.
    
    return Apache2::Const::OK;
}

# Create and set login cookie
sub authen_cred {
    my ($self, $r, @credentials) = @_;
    
    my ($username, $password) = @credentials;
    
    # Validate credentials (implement your logic)
    return unless $self->_check_credentials($r, $username, $password);
    
    # Create session key
    my $timestamp = time();
    my $signature = $self->_create_signature($username, $timestamp);
    my $session_key = join(':', $username, $timestamp, $signature);
    
    return $session_key;
}

# Credential validation (customize this)
sub _check_credentials {
    my ($self, $r, $username, $password) = @_;
    
    # Replace with your actual authentication logic
    # e.g., database lookup, LDAP, etc.
    
    return unless $username && $password;
    
    # Example placeholder
    return 1;
}

# Create session signature (customize this)
sub _create_signature {
    my ($self, $username, $timestamp) = @_;
    
    # Use a proper HMAC or encryption in production
    # This is just a placeholder
    my $secret = 'your_secret_key_here';
    
    # Example: simple hash (use Digest::SHA in production)
    return substr($username . $timestamp . $secret, 0, 32);
}

1;

__END__

=head1 CONFIGURAZIONE APACHE

Esempio di configurazione per Apache 2.4:

    LoadModule perl_module modules/mod_perl.so
    
    PerlModule Auth_AC::AuthCookieHandler
    
    # Configurazione cookie
    PerlSetVar MyAuthPath /
    PerlSetVar MyAuthCookieName MySessionCookie
    PerlSetVar MyAuthLoginScript /login
    PerlSetVar MyAuthExpires +1h
    PerlSetVar MyAuthSessionTimeout 3600
    
    # Area protetta
    <Location /protected>
        AuthType Auth_AC::AuthCookieHandler
        AuthName MyAuth
        PerlAuthenHandler Auth_AC::AuthCookieHandler->authenticate
        PerlAuthzHandler Auth_AC::AuthCookieHandler->authorize
        Require valid-user
    </Location>
    
    # Pagina di login (non protetta)
    <Location /login>
        SetHandler perl-script
        PerlResponseHandler Auth_AC::AuthCookieHandler->login
    </Location>

=head1 NOTE IMPORTANTI

=over 4

=item * Cancellazione Cookie

Per cancellare un cookie dal browser, si deve inviare un cookie con lo
stesso nome ma con data di scadenza nel passato. Questo viene fatto nel
metodo C<_expire_cookie()> usando C<-expires => '-1d'>.

=item * Risposta 403

Quando C<authen_ses_key> ritorna C<undef>, normalmente Apache2::AuthCookie
reindirizza alla pagina di login. Per ottenere invece un HTTP 403, il
metodo C<authenticate()> è stato sovrascritto per controllare una nota
speciale e restituire C<HTTP_FORBIDDEN>.

=item * Sicurezza

In produzione, assicurarsi di:

- Usare HTTPS
- Implementare firma/cifratura sicura per i session key
- Validare correttamente le credenziali
- Usare un secret key robusto e non hardcoded

=back

=head1 AUTHOR

Your Name

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
