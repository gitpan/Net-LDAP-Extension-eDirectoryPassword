use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::LDAP::Extension::eDirectoryPassword',
    VERSION_FROM      => 'eDirectoryPassword.pm', # finds $VERSION
    PREREQ_PM         => { Net::LDAP, Net::LDAP::Extension, Convert::ASN1 },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'eDirectoryPassword.pm', # retrieve abstract from module
       AUTHOR         => 'Guy Antony Halse <guy@ru.ac.za>') : ()),
    'dist'            => { COMPRESS => 'gzip', SUFFIX => 'gz' },
);
