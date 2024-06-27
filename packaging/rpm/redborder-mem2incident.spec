Name: redborder-mem2incident
Version: %{__version}
Release: %{__release}%{?dist}

License: AGPL 3.0
URL: https://github.com/redBorder/redborder-mem2incident
Source0: %{name}-%{version}.tar.gz

BuildRequires: go rsync gcc git

Summary: rpm used to install redborder-mem2incident in a redborder ng
Group:   Development/Libraries/Go

%global debug_package %{nil}

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build
export GOPATH=${PWD}/gopath
export PATH=${GOPATH}:${PATH}

mkdir -p $GOPATH/src/github.com/redBorder/redborder-mem2incident
rsync -az --exclude=packaging/ --exclude=resources/ --exclude=gopath/ ./ $GOPATH/src/github.com/redBorder/redborder-mem2incident
cd $GOPATH/src/github.com/redBorder/redborder-mem2incident
make

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/redborder-mem2incident

export PARENT_BUILD=${PWD}
export GOPATH=${PWD}/gopath
export PATH=${GOPATH}:${PATH}
pushd $GOPATH/src/github.com/redBorder/redborder-mem2incident
prefix=%{buildroot}/usr make install
popd
install -D -m 0644 resources/systemd/redborder-mem2incident.service %{buildroot}/usr/lib/systemd/system/redborder-mem2incident.service

cp config.yml.default %{buildroot}/etc/redborder-mem2incident/

%clean
rm -rf %{buildroot}

%pre

%post
systemctl daemon-reload
mkdir -p /var/log/redborder-mem2incident
[ -f /usr/lib/redborder/bin/rb_rubywrapper.sh ] && /usr/lib/redborder/bin/rb_rubywrapper.sh -c


%files
%defattr(0755,root,root)
/usr/bin/redborder-mem2incident
%defattr(644,root,root)
/usr/lib/systemd/system/redborder-mem2incident.service
/etc/redborder-mem2incident/config.yml.default

%doc

%changelog
* Thu Jun 27 2024 Miguel Negrón <manegron@redborder.com> - 0.0.1
- First spec version
