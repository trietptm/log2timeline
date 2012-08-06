#################################################################################################
#      MAKEFILE
#################################################################################################
# This is the makefile for log2timeline.
#
# Copyright 2009-2011 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
#
#  This file is part of log2timeline.
#
#    log2timeline is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    log2timeline is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with log2timeline.  If not, see <http://www.gnu.org/licenses/>.

use ExtUtils::MakeMaker;

WriteMakefile(
  'NAME'  => 'Log2t',
  'ABSTRACT' => 'An automatic tool to extract super timelines from files',
  'AUTHOR' => 'kristinn@log2timeline.net',
  'PREREQ_PM' => {
    # require the following libraries 
    "Archive::Zip" => "1.18",
    "DBI" => "1.52",
    "DateTime" => "0.41",
    "DateTime::TimeZone" => "0",
    "Encode" => "0",
    "Fcntl" => "0",
    "File::Copy" => "0",
    "Digest::MD5" => "0",
    "Getopt::Long" => "0",
    "HTML::Scrubber" => "0",
    "Image::ExifTool" => "0",
    "Net::Pcap" => "0", 
    "NetPacket::Ethernet" => "0",
    "NetPacket::IP" => "0",
    "NetPacket::TCP" => "0",
    "NetPacket::UDP" => "0",
    "Parse::Win32Registry" => "0",
    "HTML::Parser" => "0",
    "Pod::Usage" =>  "0",
    "Time::localtime" => "0",
    "LWP::UserAgent" => "0",
    "XML::LibXML::Common" => "0",
    "XML::LibXML" => "0",
    "DBD::SQLite" => "0",
    "Carp::Assert" => "0",
    "Date::Manip" => "0",
    "Carp" => "0",
    "version" => "0",
    "Data::Hexify" => "0",
    "Params::Validate" => "0",
    "File::Mork" => "0.3",
    "Math::BigInt" => "0",
    "Digest::CRC" => "0.14",
    "DateTime::Format::Strptime" => "0",
    "Mac::PropertyList" => "0",
    "Test::More" => "0.88",
    #"Text::CSV" => "0",
    #"Switch" => "0",
  },
  'VERSION_FROM' => 'lib/Log2t/Common.pm', # finds $VERSION
  'LICENSE' => 'gpl',  
  'EXE_FILES' => [ 'log2timeline', 'timescanner', 'l2t_process', 'faersluskra2timalina' ],  
  'INSTALLSCRIPT' => '/usr/local/bin/'
);
