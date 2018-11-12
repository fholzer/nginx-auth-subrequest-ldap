Name:       nginx-auth-subrequest-ldap
Version:    %{PKGVERSION}
Release:    %{PKGRELEASE}%{?dist}
Source0:    %{name}-v%{version}.tar.gz
Summary:    LDAP auth subrequest backend for nginx
License:    proprietary
Packager:   %{packager}

ExclusiveArch:  %{go_arches}
BuildRequires:  golang

%{?systemd_requires}
BuildRequires:  systemd

Requires: nginx

%description
Provides LDAP authentication for nginx via the http_auth_request API.

%prep
GO_BUILD_DIR=$RPM_BUILD_DIR/go/src/github.com/fholzer/%{name}
cd $RPM_BUILD_DIR
mkdir -p $GO_BUILD_DIR
tar --strip=2 -C $GO_BUILD_DIR -xf %{SOURCE0}

%build
GO_BUILD_DIR=$RPM_BUILD_DIR/go/src/github.com/fholzer/%{name}
export GOPATH=$RPM_BUILD_DIR/go/
cd $GO_BUILD_DIR
GOOS=linux go build -ldflags="-s -w"

%install
GO_BUILD_DIR=$RPM_BUILD_DIR/go/src/github.com/fholzer/%{name}

mkdir -p $RPM_BUILD_ROOT/%{_bindir}
cp $GO_BUILD_DIR/%{name} $RPM_BUILD_ROOT/%{_bindir}

mkdir -p $RPM_BUILD_ROOT/etc/ldap
cp $GO_BUILD_DIR/examples/systemd/config.ini $RPM_BUILD_ROOT/etc/ldap/

mkdir -p $RPM_BUILD_ROOT/%{_unitdir}
cp $GO_BUILD_DIR/examples/systemd/nginx-auth-subrequest-ldap.service $RPM_BUILD_ROOT/%{_unitdir}
cp $GO_BUILD_DIR/examples/systemd/nginx-auth-subrequest-ldap.socket $RPM_BUILD_ROOT/%{_unitdir}

mkdir -p $RPM_BUILD_ROOT/var/log/nginx-auth-subrequest-ldap


%files
%defattr(644,root,root,755)
%config(noreplace) %{_sysconfdir}/ldap/config.ini
%{_unitdir}/nginx-auth-subrequest-ldap.service
%{_unitdir}/nginx-auth-subrequest-ldap.socket

%defattr(755,root,root,755)
%{_bindir}/nginx-auth-subrequest-ldap

%dir /var/log/nginx-auth-subrequest-ldap

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf %{_tmppath}/%{name}
rm -rf %{_topdir}/BUILD/%{name}

%changelog
* Wed Oct 29 2018 - fholzer@gvcgroup.com
- Initial release
