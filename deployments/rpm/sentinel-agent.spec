Name:           sentinel-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        SentinelCore Enterprise Security Agent
License:        Proprietary
Requires:       systemd, ca-certificates
BuildRequires:  systemd-rpm-macros

%description
SentinelCore agent with mTLS telemetry, encrypted disk spooling and signed updates.

%install
install -D -m 0755 %{_sourcedir}/sentinel-agent %{buildroot}/opt/sentinel-agent/sentinel-agent
install -D -m 0644 %{_sourcedir}/sentinel-agent.service %{buildroot}%{_unitdir}/sentinel-agent.service
install -d -m 0700 %{buildroot}/var/lib/sentinel

%post
%systemd_post sentinel-agent.service

%preun
%systemd_preun sentinel-agent.service

%postun
%systemd_postun_with_restart sentinel-agent.service

%files
/opt/sentinel-agent/sentinel-agent
%{_unitdir}/sentinel-agent.service
%dir %attr(0700,root,root) /var/lib/sentinel

%changelog
* Sun Sep 06 2026 SentinelCore <security@sentinelcore.invalid> - 0.1.0-1
- Initial enterprise beta package
