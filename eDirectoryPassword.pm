package Net::LDAP::Extension::eDirectoryPassword;

require Net::LDAP::Extension;
require Convert::ASN1;
use constant NMASLDAP_GET_PASSWORD_REQUEST => "2.16.840.1.113719.1.39.42.100.13";
use constant NMASLDAP_GET_PASSWORD_RESPONSE => "2.16.840.1.113719.1.39.42.100.14";
use constant NMAS_LDAP_EXT_VERSION => 1;

$VERSION = "0.00_01";
@ISA = qw(Net::LDAP::Extension);

# prepare to BER encode the request
my $passwdRequest = Convert::ASN1->new;
$passwdRequest->prepare (q<SEQUENCE { nmasver INTEGER, reqdn OCTET STRING } >);

# prepare to BER decode the response
my $passwdResponse = Convert::ASN1->new;
$passwdResponse->prepare (q<SEQUENCE { nmasver INTEGER, err INTEGER, passwd OCTET STRING }>);

# get an universal password
sub Net::LDAP::get_edir_password {
	my $ldap = shift;
	my $requestdn = shift;
	
	my $res = $ldap->extension (
	  name => NMASLDAP_GET_PASSWORD_REQUEST,
	  value => $passwdRequest->encode (
	    'nmasver' => NMAS_LDAP_EXT_VERSION, 
	    'reqdn' => $requestdn,
	  ),
	);
	
	bless $res;
}

# return a previously fetched password
sub edir_password {
	my $self = shift;

	if ($self->response_name() eq NMASLDAP_GET_PASSWORD_RESPONSE) {
		my $output = $passwdResponse->decode ($self->response());
		if (!$output->{'err'}) {
			return $output->{'passwd'};
		}
	}
	return undef;
}

1;

__END__

=head1 NAME

Net::LDAP::Extension::eDirectoryPassword - LDAPv3 extension object to retrieve eDirectory Universal Password

=head1 SYNOPSIS

 use Net::LDAP;
 use Net::LDAP::Extension::eDirectoryPassword;

 $ldap = Net::LDAP->new ("edirectory.example.org");

 $ldap->bind ('cn=admin,o=example", password => 'adminPassword');

 $mesg = $ldap->get_edir_password ('cn=user,ou=context,o=example');

 $mesg->code() || die $mesg->error();

 print "Universal Password for ", $dn, " is ", $mesg->edir_password() , "\n";

=head1 DESCRIPTION

C<Net::LDAP::Extension::eDirectoryPassword> implements Novell's
NMASLDAP_GET_PASSWORD_REQUEST extended LDAPv3 operation.  This allows you to
retrieve a cleartext Universal Password from a properly configured
eDirectory instance.

This module extends the L<Net::LDAP> object by another method.

=head1 METHODS

=over 4

=item get_edir_password ($dn)

Retrieve a cleartext Universal Password.  C<$dn> is the full distinguished
name (as a string) of the iNetOrgPerson object for which you want to
retrieve the Universal Password.

=item edir_password ()

Return the password retrieved by the previous C<get_edir_password()> call as
a string.  If no password is available, undef is returned.

This method is an extension of the L<Net::LDAP::Message> response object
returned in reply to C<get_edir_password()>.

=back

=head1 NOTES

Novell's mechanism for retrieving Universal Passwords via LDAPv3 is poorly
documented.  Perhaps the best documentation exists in the form of the
FreeRadius project's L<http://freeradius.org/> source code.  This module is
a pure Perl implementaion of their C<nmasldap_get_password()> function.

The module assumes that you've already configured your eDirectory to support
Universal Passwords, and Universal Password retrieval.  This is not
eDirectory's default configuration.  At the very least, you have to create
an administrative user and grant it specific permission to retrieve the
cleartext password.  See
L<http://www.novell.com/documentation/edir_radius/index.html>

=head1 SEE ALSO

L<Net::LDAP>,
L<Net::LDAP::Extension>
L<http://freeradius.org/>

=head1 AUTHOR

Guy Antony Halse E<lt>guy@ru.ac.zaE<gt>,

=head1 COPYRIGHT

Copyright (c) 2008, Rhodes University, All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of Rhodes University nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.
                  
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut
