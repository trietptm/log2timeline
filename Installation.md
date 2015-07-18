# Introduction #

Installing log2timeline varies greatly based on which operating system you are installing to since it requires several Perl libraries.

# Details #

## SIFT - SANS Investigate Forensic Toolkit ##

The SIFT workstation is based on Ubuntu Linux.  It contains many DFIR (forensic) tools in addition to log2timeline.

http://computer-forensics.sans.org/community/downloads

## Debian/Ubuntu ##

There is a repository for Ubuntu distributions, so you can add the following line to your /etc/apt/sources.list file:

For natty (Ubuntu 11.04) the line is:

```
deb http://log2timeline.net/pub/ natty main
```

For maverick (Ubuntu 10.10) the line is:

```
deb http://log2timeline.net/pub/ maverick main
```

And for lucid (Ubuntu 10.04) the line is:

```
deb http://log2timeline.net/pub/ lucid main
```

For karmic (Ubuntu 9.10) the line is:

```
deb http://log2timeline.net/pub/ karmic main
```

All the debian packages are signed with my personal GPG key, which can be downloaded from [here](http://log2timeline.net/gpg.asc) ([MD5](http://log2timeline.net/gpg.md5))([SHA256](http://log2timeline.net/gpg.sha256))

Download the GPG file and issue:
```
apt-key add gpg.asc
```

And then all you should need to do is:

```
apt-get update
apt-get install log2timeline-perl
```
(if your architecture is missing from the repository, please notify me so that I can update it)

## Fedora ##

log2timeline has also been added to the CERT.org forensics tool repository. So to install the tool using yum in Fedora simply add the repository and issue the following command:

```
yum install log2timeline
```

All dependencies are solved by yum.

## OpenBSD ##

The tool has also been added to the OpenBSD ports as security/log2timeline, which have been ported to other ports as well, including Mac OS X. So it should be enough to issue the command:
```
port install log2timeline
```
to get the tool to install on Mac OS X (given that you've got MacPorts installed) or on a OpenBSD system.

n.b. the Mac OS X port is old, and has not been maintained in a while.

## Windows ##

This blog entry provides detailed instructions for installing log2timeline in Windows:

http://thedigitalstandard.blogspot.com/search?q=log2timeline

## openSUSE ##

log2timeline is included in the openSUSE DFIR boot CD / boot thumbdrive:

http://susestudio.com/a/eD1wrT/dfir-opensuse-gnome-desktop-32bit

In addition, as discussed in the openSUSE DFIR portal page, openSUSE 11.4 and openSUSE 12.1 have log2timeline in the security project.

http://http://en.opensuse.org/index.php?title=Portal:Digital_Forensics_/_Incident_Response

The basic steps to install log2timeline in either openSUSE 11.4 or 12.1 are:

configure the needed repositories
```
 sudo zypper ar -f http://download.opensuse.org/repositories/security/openSUSE_12.1 security
 sudo zypper ar -f http://download.opensuse.org/repositories/devel:/languages:/perl/openSUSE_12.1 perl
```

Verify you have the above 2 repos configured correctly
```
zypper lr               
```

Install log2timeline and all needed pre-requisites
```
 sudo zypper in log2timeline
```

## Arch Linux ##

To install the tool using Arch Linux simply use the package manager to install it.

See: https://aur.archlinux.org/packages.php?ID=51651

## Source ##

To install from sources you can either grab the last source release from the download section or use git to get the latest code fresh from the repository.

Resolve all dependencies by hand (no help here, sorry)... you can always test by running "_log2timeline_ _-f_ _list_" to see if some dependencies have not yet been met.

As a partial guide, you can use the list of dependencies that opensuse uses by clicking on one of the noarch.rpm links here:
https://build.opensuse.org/package/binaries?package=log2timeline&project=security&repository=openSUSE_12.1

Untar the source (if you download the tarball), and run

```
cd log2timeline
perl Makefile.PL && make
make install (as root)
```

There should be a warning when "_perl_ _Makefile.PL_" is run if a dependency is missing.