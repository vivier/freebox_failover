%global pypi_name freebox-failover
%global srcname freebox_failover
%global __brp_python_bytecompile /bin/true
%global __brp_add_determinism /bin/true
%global __requires_exclude ^python3.12dist\\(ping3\\)$

Name:           %{pypi_name}
Version:        0.0.1
Release:        1%{?dist}
Summary:        Freebox WAN failover daemon

License:        GPL-3.0-or-later
URL:            https://github.com/vivier/freebox_failover
Source0:        %{srcname}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  systemd-rpm-macros

Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

Provides:       %{pypi_name} = %{version}-%{release}
Provides:       freebox-failover = %{version}-%{release}

%generate_buildrequires
%pyproject_buildrequires -R

%description
Monitor the Freebox WAN state and temporarily replace the gateway with a 4G
failover path. Sends Gratuitous ARP/NA/RA, uses the Freebox HTTP API, and can
notify via Free Mobile SMS.

%prep
%autosetup -n %{srcname}-%{version}
%py3_shebang_fix freebox_failover.py freebox_failover_register.py

%build
export PIP_CACHE_DIR=%{_builddir}/.pip-cache
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files freebox_failover freebox_failover_register
rm -rf %{buildroot}%{python3_sitelib}/etc %{buildroot}%{python3_sitelib}/usr
install -Dpm 644 freebox_failover.conf %{buildroot}%{_sysconfdir}/freebox_failover.conf
install -Dpm 644 systemd/freebox_failover.env %{buildroot}%{_sysconfdir}/default/freebox_failover.env
install -Dpm 644 freebox_failover.service %{buildroot}%{_unitdir}/freebox_failover.service
install -Dpm 644 cloud-init-user-data.yaml %{buildroot}%{_datadir}/freebox-failover/cloud-init-user-data.yaml

%check
# Import tests require raw socket access; skip in constrained build env
:;

%post
pip install ping3
%systemd_post freebox_failover.service

%preun
%systemd_preun freebox_failover.service

%postun
%systemd_postun_with_restart freebox_failover.service

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%config(noreplace) %{_sysconfdir}/freebox_failover.conf
%config(noreplace) %{_sysconfdir}/default/freebox_failover.env
%{_unitdir}/freebox_failover.service
%{_bindir}/freebox_failover.py
%{_bindir}/freebox_failover_register.py
%{_datadir}/freebox-failover/cloud-init-user-data.yaml

%changelog
* Tue Nov 25 2025 Laurent Vivier <laurent@vivier.eu> - 0.0.1-1
- Initial packaging with pyproject macros and systemd integration
