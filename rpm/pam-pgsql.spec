Name:		pam-pgsql
Version:	0.7.3.2
Release:	1%{?dist}
Summary:	This module provides support to authenticate against PostgreSQL tables for PAM-enabled appliations.
Packager:	Jose Arthur Benetasso Villanova <jose.arthur@gmail.com>


Group:		Applications/Databases
License:	GPL
URL:		https://github.com/pam-pgsql/pam-pgsql
Source0:	http://sourceforge.net/projects/pam-pgsql/%{name}_%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	mhash-devel postgresql-devel pam-devel
Requires:	postgresql-libs

%description
This module provides support to authenticate against PostgreSQL
tables for PAM-enabled appliations.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}


%install
# Borrowed from pam_smb.spec
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_lib}/security
install -m755 pam_pgsql.so $RPM_BUILD_ROOT/%{_lib}/security/

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc CREDITS README
/%{_lib}/security/pam_pgsql.so



%changelog
* Sun Jul 13 2008 Jose Arthur Benetasso Villanova <jose.arthur@gmail.com> 0.6.4-1
- Initial release


