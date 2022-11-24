%define with_selinux 1

Version: 1.0.1
Name: libcareplus
Summary: LibcarePlus tools
Release: 1
Group: Applications/System
License: GPLv2
Url: https://gitee.com/openeuler/libcareplus
Source0: https://gitee.com/openeuler/libcareplus/release/download/v%{version}/%{name}-%{version}.tar.gz

BuildRequires: elfutils-libelf-devel libunwind-devel gcc systemd

%if 0%{with selinux}
BuildRequires: checkpolicy
BuildRequires: selinux-policy-devel
%endif

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if 0%{with selinux}
Requires:      libcareplus-selinux = %{version}-%{release}
%endif

%description
LibcarePlus userland tools

%if 0%{with selinux}

%package selinux
Summary: SELinux package for LibcarePlus/QEMU integration
Group: System Environment/Base
Requires(post): selinux-policy-base, policycoreutils
Requires(postun): policycoreutils
%description selinux
This package contains SELinux module required to allow for
LibcarePlus interoperability with the QEMU run by sVirt.

%endif


%package devel
Summary: LibcarePlus development package
Group: System Environment/Development Tools
%description devel
LibcarePlus devel files.


%prep
%setup -q
%autopatch -p1

%build
cd src
sh ./config
cd ../
make -C src
%if 0%{with selinux}
make -C dist/selinux
%endif

%install
%{__rm} -rf %{buildroot}

make -C src install \
        DESTDIR=%{buildroot} \
        bindir=%{_bindir} \
        libexecdir=%{_libexecdir}

%if 0%{with selinux}
make -C dist/selinux install \
        DESTDIR=%{buildroot}
%endif


install -m 0644 -D dist/libcare.preset %{buildroot}%{_presetdir}/90-libcare.preset
install -m 0500 scripts/pkgbuild %{buildroot}%{_bindir}/libcare-pkgbuild
install -m 0500 scripts/de-offset-syms.awk %{buildroot}%{_bindir}/de-offset-syms.awk
install -m 0644 -D scripts/example_info %{buildroot}/usr/share/libcareplus/qemu_example_info

%pre
/usr/sbin/groupadd libcare -r 2>/dev/null || :
/usr/sbin/usermod -a -G libcare qemu 2>/dev/null || :

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/libcare-ctl
%{_presetdir}/90-libcare.preset

%files devel
%defattr(-,root,root)
%{_bindir}/libcare-cc
%{_bindir}/libcare-patch-make
%{_bindir}/libcare-dump
%{_bindir}/kpatch_gensrc
%{_bindir}/kpatch_strip
%{_bindir}/kpatch_make
%{_bindir}/libcare-server
%{_bindir}/libcare-client
%{_bindir}/libcare-pkgbuild
%{_bindir}/de-offset-syms.awk
/usr/share/libcareplus/qemu_example_info

%if 0%{with selinux}

%files selinux
%defattr(-,root,root,-)
%attr(0600,root,root) %{_datadir}/selinux/packages/libcare.pp

%post selinux
. /etc/selinux/config
FILE_CONTEXT=/etc/selinux/${SELINUXTYPE}/contexts/files/file_contexts
cp ${FILE_CONTEXT} ${FILE_CONTEXT}.pre

/usr/sbin/semodule -i %{_datadir}/selinux/packages/libcare.pp

# Load the policy if SELinux is enabled
if ! /usr/sbin/selinuxenabled; then
    # Do not relabel if selinux is not enabled
    exit 0
fi

/usr/sbin/fixfiles -C ${FILE_CONTEXT}.pre restore 2> /dev/null

rm -f ${FILE_CONTEXT}.pre

exit 0

%postun selinux
if [ $1 -eq 0 ]; then
    . /etc/selinux/config
    FILE_CONTEXT=/etc/selinux/${SELINUXTYPE}/contexts/files/file_contexts
    cp ${FILE_CONTEXT} ${FILE_CONTEXT}.pre

    # Remove the module
    /usr/sbin/semodule -n -r libcare > /dev/null 2>&1

    /usr/sbin/fixfiles -C ${FILE_CONTEXT}.pre restore 2> /dev/null
fi
exit 0

%endif

%changelog
* Thu Nov 24 2022 yezengruan <yezengruan@huawei.com> 1.0.1-1
- libcareplus update to version 1.0.1

* Tue Dec 08 2020 Ying Fang <fangying1@huawei.com> - 0.1.4-1
- Init the libcareplus package spec
