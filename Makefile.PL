use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::IEC104',
    VERSION_FROM      => 'lib/Net/IEC104.pm', # finds $VERSION
    PREREQ_PM         => { Event::Lib => 1.03, IO::Socket::INET => 1.29, Carp => 1.0,
			Date::Manip=>1.0 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/IEC104.pm', # retrieve abstract from module
       AUTHOR         => 'Vladimir Lettiev <thecrux@gmail.com>') : ()),
);
