Name:		log2timeline
Version:	0.60
Release:	1%{?dist}
Summary:	A framework for timeline creation and analysis

Group:		Applications/Engineering
License:	GPLv2
URL:		http://log2timeline.net
Source0:	http://log2timeline.net/files/%{name}_0.60.tgz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	perl,perl(CPAN),perl(ExtUtils::MakeMaker)
Requires:	perl-Archive-Zip >= 1.18, perl-Carp-Assert, perl-DBD-SQLite, perl-Data-Hexify, perl-DateTime >= 0.41, perl-DateTime-Format-Strptime, perl-DateTime-TimeZone, perl-Digest-CRC >= 0.14, perl-File-Mork >= 0.3, perl-Glib, perl-Gtk2, perl-HTML-Scrubber, perl-Image-ExifTool, perl-Mac-PropertyList, perl-Net-Pcap, perl-NetPacket, perl-Params-Validate, perl-Parse-Win32Registry, perl-XML-LibXML, perl-XML-LibXML-Common

%description
A framework to for timeline creation and analysis.

Log2timeline provides a framework to automatically extract timeline
information out of various log files and artifacts found on various
operating systems.  The framework then outputs the timeline information
in the chosen output format that can then be viewed using already
existing timeline analysis tools, or other tools to inspect the timeline.

%define perl_vendorlib %(eval "`perl -V:installvendorlib`"; echo $installvendorlib)
%define perl_vendorarch %(eval "`perl -V:installvendorarch`"; echo $installvendorarch)

%prep
%setup -q -n log2timeline


%build
CFLAGS="$RPM_OPT_FLAGS" %{__perl} Makefile.PL INSTALLDIRS=vendor
%{__perl} -pi -e 's/^\tLD_RUN_PATH=[^\s]+\s*/\t/' Makefile
make %{?_smp_mflags} OPTIMIZE="$RPM_OPT_FLAGS"

#perl Makefile.PL INSTALL_BASE=/usr/
#make

%install
rm -rf $RPM_BUILD_ROOT
make pure_install PERL_INSTALL_ROOT=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -type f -a \( -name .packlist \
-o \( -name '*.bs' -a -empty \) \) -exec rm -f {} ';'
find $RPM_BUILD_ROOT -type d -depth -exec rmdir {} 2>/dev/null ';'
chmod -R u+w $RPM_BUILD_ROOT/*
# Pre-%files stage inventory
find $RPM_BUILD_ROOT -not -type d -printf "%%%attr(%%m,root,root) %%p\n" | sed -e "s|$RPM_BUILD_ROOT||g" > %{_tmppath}/%{name}_contents.txt
sed -i "s|man/.*|\0.gz|g" %{_tmppath}/%{name}_contents.txt

#make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT


%files -f %{_tmppath}/%{name}_contents.txt
%defattr(-,root,root,-)
%doc CHANGELOG LICENSE ROADMAP docs/*


%changelog

