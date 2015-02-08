%{!?log_dir:%global log_dir %{_localstatedir}/log/slog}
%{!?sslogger_user:%global sslogger_user slogger}
%{!?sslogger_group:%global sslogger_group sloggers}

Summary: A keystroke logging utility for privileged user escalation
Name: sslogger
Version: 0.98.14
Release: 1%{?dist}
License: GPLv3+
Group: User Interface/Desktops
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
#URL: http://sslogger.sourceforge.net
URL:  http://sourceforge.net/downloads/%{name}/%{name}-%{version}
#Source0: http://downloads.sourceforge.net/%{name}/%{name}-%{version}.tar.gz
Source0: http://sourceforge.net/downloads/%{name}/%{name}-%{version}/tgz/%{name}-%{version}.tar.gz
Requires: bash logrotate 
Requires(pre): shadow-utils util-linux gnutls
BuildRequires: gnutls-devel 
%description
A keystroke logging utility for privileged user escalation

%package slogd
Summary: Secure log server daemon for sslogger
Group: User Interface/Desktops
Requires: gnutls sslogger gnutls-utils
%if 0%{?fedora} >= 10
Requires: gnutls-utils
%endif
%description slogd
Secure log server daemon for sslogger

%pre
getent group sloggers > /dev/null || groupadd  %{sslogger_group} -r &>/dev/null
getent passwd slogger > /dev/null ||/usr/sbin/useradd -c "Privilege keystroke logger"  %{sslogger_user} -s /sbin/nologin -r -M  -g sloggers -d %{log_dir} &>/dev/null

%preun slogd
if [ $1 -eq 0 ]; then
  #run removal scripts here
  chkconfig --del sslogger-slogd
fi


%post slogd
chkconfig sslogger-slogd off
#TODO: below is a kludge to fix the slogd-server code
#touch %{log_dir}/slogd.log
#chmod 640 %{log_dir}/slogd.log
#chown %{sslogger_user}.%{sslogger_group} %{log_dir}/slogd.log

%prep
%setup -q
make clean

%build
export CFLAGS="$RPM_OPT_FLAGS -DLOG_DIR=%{_localstatedir}/log/slog -DCONF_FILE=%{_sysconfdir}/sslogger.d/sslogger.conf"
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/%{_localstatedir}/log/slog
chmod 750 %{buildroot}/%{_localstatedir}/log/slog
make install DESTDIR=%{buildroot} VERSION=%{version}
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
cp -p sslogger_rotate %{buildroot}%{_sysconfdir}/logrotate.d/sslogger
cp -p slogd_rotate %{buildroot}%{_sysconfdir}/logrotate.d/sslogger-slogd
mkdir -p %{buildroot}/%{_localstatedir}/run/sslogger
mkdir -p %{buildroot}/%{_sysconfdir}/pki/slog/CA
mkdir -p %{buildroot}/%{_sysconfdir}/pki/slog/private
mkdir -p %{buildroot}/%{_sysconfdir}/sslogger.d/tls

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/slog
%{_bindir}/sreplay
#%{_bindir}/rslog
%attr (6555,%{sslogger_user},%{sslogger_group}) %{_bindir}/sslogger
%attr(775,%{sslogger_user},%{sslogger_group})  %{log_dir}
%config(noreplace) %{_sysconfdir}/sslogger.d/sslogger.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/sslogger
%{_mandir}/man5/sslogger.conf.5.gz
%{_mandir}/man8/sreplay.8.gz
%{_mandir}/man8/sslogger.8.gz
%{_mandir}/man8/slog.8.gz

%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/TODO
%doc %{_docdir}/%{name}-%{version}/LICENSE
%doc %{_docdir}/%{name}-%{version}/rslog
#TLS certs
%dir %{_sysconfdir}/pki/slog
%dir %{_sysconfdir}/pki/slog/CA
%dir %{_sysconfdir}/pki/slog/private

%files slogd
%defattr(-,root,root,-)
%{_sbindir}/sslogger-slogd
%config(noreplace) %{_sysconfdir}/sslogger.d/sslogger-slogd.conf
%config(noreplace) %{_sysconfdir}/sysconfig/sslogger-slogd
%config(noreplace) %{_sysconfdir}/logrotate.d/sslogger-slogd
%{_mandir}/man8/sslogger-slogd.8.gz
%dir %{_localstatedir}/run/sslogger
%dir %{_sysconfdir}/sslogger.d
%dir %{_sysconfdir}/sslogger.d/tls
%attr(775,%{sslogger_user},%{sslogger_group}) %{_localstatedir}/run/sslogger
%{_sysconfdir}/init.d/sslogger-slogd
%dir %{_docdir}/%{name}-%{version}
%doc %{_docdir}/%{name}-%{version}/mkSlogCerts
%doc %{_docdir}/%{name}-%{version}/README


%changelog
* Wed Dec 15 2010 <ebrand@fedoraproject.org> Ver 0.98.14-1
- incorporated backward gnutls/gcrypt routines.
- Will now build on RHEL 4 and Sol10 with  SFWgnutls(v0.9.x)  package
- added \r\n at EOL  when logging remote commands

* Mon Dec 13 2010 <ebrand@fedoraproject.org> Ver 0.98.12
- fixed bug: sreplay rewind beyond filepos 0 issue
- sslogger: fix bug truncating reason when passed on cmd line
- Added logging of sslogger-slogd child pid to syslog and slogd.log
- sreplay handel kill sig

* Mon Nov 1 2010 <ebrand@fedoraproject.org> Ver 0.97-1
- Now builds on Solaris with sfw gnutls(1.4.x)
- sslogger: bug fix min cmd length requirement

* Thu Jul 1 2010 <ebrand@fedoraproject.org> 0.96-2
- spec file typo fixes

* Tue Jun 21 2010  <ebrand@fedoraproject.org> 0.96-1
- lateset upstream release
- added -r "Reason" to sslogger
- ssloger now display remote slogd server and logID
- sslogger.c bug fixed when writing to localfile using -c and local logging disabled 
- Config file moved to /etc/sslogger.d/sslogger.conf
- fixed cordump when tls session is NULL

* Sat Jun 8 2010 <ebrand@fedoraproject.org> 0.95-2
- rpm row claims ownership of directory /usr/share/doc/sslogger-<version>

* Mon Jun 6 2010 <edbrand@brandint.com> - 0.95-1
- latest upteam release

* Mon Jun 6 2010 <edbrand@brandint.com> - 0.94-4
- init script fixes

* Mon Jun 6 2010 <edbrand@brandint.com> - 0.94-3
- remaned /var/run/slogd/ /var/run/sslogger
- Renamed slogd binaries sslogger-slogd to match package name

* Mon May 31 2010 <edbrand@brandint.com> - 0.94-2
- Spec file fixes: 
- pid filename changed to match package
- changed daemon name to match package name

* Sun May 2 2010 <edbrand@brandint.com> - 0.94-1
- Fixed bugs in tlsclient, updated release 
- Added '-l' option to sslogger
- Added rslog
- Split sslogger-slogd into its own package
- added -lgcrypt in Makefile

* Wed Dec 29 2009 Ed Brand <edbrand@brandint.com> - 0.91-10
- Changed $define to $global in spec file

* Wed Dec 29 2009 Ed Brand <edbrand@brandint.com> - 0.91-9
- Notify slog server and gracefully termiate tls session when 
- running -c <cmd> with log_all_cmds=0

* Wed Dec 29 2009 Ed Brand <edbrand@brandint.com> - 0.91-8
- changed popen to dump stderr to stdout

* Wed Dec 29 2009 Ed Brand <edbrand@brandint.com> - 0.91-7
- fixed SIGPIP on server close connection

* Wed Dec 29 2009 Ed Brand <edbrand@brandint.com> - 0.91-1
- added remote tls logging and slogd server

* Sun Aug 23 2009 Ed Brand <edbrand@brandint.com> - 0.9-50
- fixed to logrotate

* Tue Jul 14 2009 Ed Brand <edbrand@brandint.com> - 0.9-49
- fixes to specfile: _sysconfdir

* Sat Jul 11 2009 Ed Brand <<edbrand@brandint.com> - 0.9-48
- Misc spec file fixes

* Thu Jul 09 2009 Ed Brand <edbrand@brandint.com> - 0.9-46
- Updates to man pages

* Thu Jul 09 2009 Ed Brand <<edbrand@brandint.com> - 0.9-45
- Fixes to $log_dir permission

* Sun Jul 05 2009 Ed Brand <edbrand@brandint.com> - 0.9-40
- Split man files into slog, sslogger and sreplay
- Chmod 775 $log_dir to allow normal user access
- Add check to slog to disallowe passing '-' when -c option is used

* Tue May 18 2009 Ed Brand <edbrand@brandint.com> - 0.9-32
- removed $global

* Sun Mar 29 2009 Ed Brand <edbrand@brandint.com> - 0.9-30
- Change Licence to GPLv3
- Misc. spec file fixes

