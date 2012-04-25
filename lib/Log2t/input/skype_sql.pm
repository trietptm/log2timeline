#################################################################################################
#    SKYPE_SQL
#################################################################################################
# this script reads the main database of Skype.  The file is a SQLITE
# database that contains among others history of chats and calls made in Skype
#
# This is just the first version, which is very limited in scope, really only tackles chat messages
# and calls made, no real parsing of the database, just a simple parsing.  Future versions should
# include updates that include more advanced parsing of the database.
#
# The location of the file is usually here:
# Windows XP:
#   \documents and settings\<user profile>\application data\<skype username>\
# Mac OS X:
#  /Users/<username>/Library/Application Support/Skype/<skype username>
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 17/04/11
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
#
# This script uses part of the code ff3histview, previously published
# by the same author
package Log2t::input::skype_sql;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use DBI;
use File::Copy;
use Log2t::Numbers;
use Log2t::Time;
use Log2t::Common;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

$VERSION = '0.1';

sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we are dealing with a binary file (only one entry returned)
    $self->{'multi_line'} = 0;

    bless($self, $class);

    return $self;
}

sub init() {
    my $self = shift;

    # initialize variables
    $self->{'db_lock'} = 0;

    return 1;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a Skype database";
}

#       get_time
# The main "juice", the routine that is called to extract all timestamps
# from the database.  The database returns a reference to a hash that
# contains all the timestamp objects extracted from the database
sub get_time {
    my $self = shift;

    # define needed variables
    my $return = 1;
    my $temp;
    my ($sth, $sql);
    my $result;
    my $dump;

    # the container for the timestamps
    my %ret_lines = undef;

    # the index to the container
    my $ret_index = 0;

    # check if this is real Chrome database
    $self->{'vdb'}->prepare('SELECT friendlyname FROM Chats LIMIT 1') || ($return = 0);

    if (!$return) {
        print STDERR "[Skype] The database is not a correct Skype database";
        return $return;
    }

    # we now know that we have a Skype SQLITE database, let's continue

    ##################################################################
    # the structure/schema of the Chats table
    ##################################################################
    #  id INTEGER NOT NULL PRIMARY KEY,
    #  is_permanent INTEGER,
    #  name TEXT,
    #  options INTEGER,
    #  friendlyname TEXT,
    #  description TEXT,
    #  timestamp INTEGER,
    #  activity_timestamp INTEGER,
    #  dialog_partner TEXT,
    #  adder TEXT,
    #  type INTEGER,
    #  mystatus INTEGER,
    #  myrole INTEGER,
    #  posters TEXT,
    #  participants TEXT,
    #  applicants TEXT,
    #  banned_users TEXT,
    #  name_text TEXT,
    #  topic TEXT,
    #  topic_xml TEXT,
    #  guidelines TEXT,
    #  picture BLOB,
    #  alertstring TEXT,
    #  is_bookmarked INTEGER,
    #  passwordhint TEXT,
    #  unconsumed_suppressed_msg INTEGER,
    #  unconsumed_normal_msg INTEGER,
    #  unconsumed_elevated_msg INTEGER,
    #  unconsumed_msg_voice INTEGER,
    #  activemembers TEXT,
    #  state_data BLOB,
    #  lifesigns INTEGER,
    #  last_change INTEGER,
    #  first_unread_message INTEGER,
    #  pk_type INTEGER,
    #  dbpath TEXT,
    #  split_friendlyname TEXT,
    #  conv_dbid INTEGER,
    #  extprop_hide_from_history INTEGER,
    #  extprop_chat_aux_type INTEGER,
    #  extprop_chat_sort_order INTEGER,
    #  extprop_mark_read_immediately INTEGER
    #-----------------------------------------------------------------
    #
    ##################################################################
    # the structure/schema of the Accounts table
    ##################################################################
#   id INTEGER NOT NULL PRIMARY KEY,
#  is_permanent INTEGER,
#  status INTEGER,
#  pwdchangestatus INTEGER,
#  logoutreason INTEGER,
#  commitstatus INTEGER,
#  suggested_skypename TEXT,
#  skypeout_balance_currency TEXT,
#  skypeout_balance INTEGER,
#  skypeout_precision INTEGER,
#  skypein_numbers TEXT,
#  subscriptions TEXT,
#  cblsyncstatus INTEGER,
#  offline_callforward TEXT,
#  chat_policy INTEGER,
#  skype_call_policy INTEGER,
#  pstn_call_policy INTEGER,
#  avatar_policy INTEGER,
#buddycount_policy INTEGER, timezone_policy INTEGER, webpresence_policy INTEGER, phonenumbers_policy INTEGER, voicemail_policy INTEGER, authrequest_policy INTEGER, ad_policy INTEGER, partner_optedout TEXT, service_provider_info TEXT, registration_timestamp INTEGER, nr_of_other_instances INTEGER, owner_under_legal_age INTEGER, type INTEGER, skypename TEXT, pstnnumber TEXT, fullname TEXT, birthday INTEGER, gender INTEGER, languages TEXT, country TEXT, province TEXT, city TEXT, phone_home TEXT, phone_office TEXT, phone_mobile TEXT, emails TEXT, homepage TEXT, about TEXT, profile_timestamp INTEGER, received_authrequest TEXT, displayname TEXT, refreshing INTEGER, given_authlevel INTEGER, aliases TEXT, authreq_timestamp INTEGER, mood_text TEXT, timezone INTEGER, nrof_authed_buddies INTEGER, ipcountry TEXT, given_displayname TEXT, availability INTEGER, lastonline_timestamp INTEGER, capabilities BLOB, avatar_image BLOB, assigned_speeddial TEXT, lastused_timestamp INTEGER, authrequest_count INTEGER, assigned_comment TEXT, alertstring TEXT, avatar_timestamp INTEGER, mood_timestamp INTEGER, rich_mood_text TEXT, synced_email BLOB, set_availability INTEGER, options_change_future BLOB, cbl_profile_blob BLOB, authorized_time INTEGER, sent_authrequest TEXT, sent_authrequest_time INTEGER, sent_authrequest_serial INTEGER, buddyblob BLOB, cbl_future BLOB, node_capabilities INTEGER, node_capabilities_and INTEGER, revoked_auth INTEGER, added_in_shared_group INTEGER, in_shared_group INTEGER, authreq_history BLOB, profile_attachments BLOB, stack_version INTEGER, offline_authreq_id INTEGER, verified_email BLOB, verified_company BLOB);
#-----------------------------------------------------------------
#
    ##################################################################
    # the structure/schema of the SMSes table
    ##################################################################
#   id INTEGER NOT NULL PRIMARY KEY
#  is_permanent INTEGER
#  type INTEGER
#  status INTEGER
#  failurereason INTEGER
#  is_failed_unseen INTEGER
#  timestamp INTEGER, price INTEGER, price_precision INTEGER, price_currency TEXT, reply_to_number TEXT, target_numbers TEXT, target_statuses BLOB, body TEXT, chatmsg_id INTEGER, extprop_sms_guid BLOB, extprop_sms_rendered_body TEXT, extprop_sms_render_version INTEGER, extprop_sms_aux_type INTEGER, extprop_sms_aux_timestamp INTEGER, extprop_sms_aux_status INTEGER);
#
#-----------------------------------------------------------------

    # The tables in main.db that contain a timestamp are the following:
    #  Account    - account last registered online
    #  SMSes    - time when SMS is sent
    #  Chats    - timestamp when a message is sent
    #  Alerts    - Timestamp when an alert is sent
    #  Calls    - when a call is made and when it is done (duration)
    #  CallMembers  -
    #  Contacts  - various timestamps related to the contacts history
    #  Conversations  -
    #  Messages  - various timestamps relating to messages
    #  Participants  -

# so .... basically lots of coding left... need to map out all the tables, it's content and the relationship between them all....

    # dialog_partner - the one that is being talked to  (not null)
    #
    # Construct the SQL statement to extract the needed data
    $sql =
      "SELECT Chats.friendlyname,Messages.author,Messages.from_dispname,Messages.body_xml,Messages.timestamp,Messages.dialog_partner 
FROM Chats,Messages
WHERE Chats.name = Messages.chatname";

    # Tengja vid Messages tofluna
    $sth    = $self->{'vdb'}->prepare($sql);
    $result = $sth->execute();

    # load the result into an array
    while ($dump = $sth->fetchrow_hashref) {
        $self->{'r_type'} = 'chat';
        $self->{'r_line'} = $dump;

        $ret_lines{ $ret_index++ } = $self->_parse_timestamp;
    }

    $sql =
      "SELECT timezone_policy,fullname,country,given_displayname,lastonline_timestamp,skypename FROM Accounts";
    $sth    = $self->{'vdb'}->prepare($sql);
    $result = $sth->execute();

    # load the result into an array
    while ($dump = $sth->fetchrow_hashref) {
        $self->{'r_type'} = 'account';
        $self->{'r_line'} = $dump;

        $ret_lines{ $ret_index++ } = $self->_parse_timestamp;
    }

    # return the container
    return \%ret_lines;
}

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose
# just the way it is defined right now.
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#       end
# A subroutine that closes the file, after it has been parsed
# @return An integer indicating that the close operation was successful
sub end() {
    my $self = shift;

    # disconnect the database
    $self->{'vdb'}->disconnect if defined $self->{'vdb'};

    # check to see if database is locked, then delete temp file
    if ($self->{'db_lock'}) {

        #print STDERR "Deleting temporary history file, $db_file \n";
        unlink(${ $self->{'name'} });
        unlink(${ $self->{'name'} } . '-journal') if -e ${ $self->{'name'} } . '-journal';
    }
}

#       parse_line
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# The default structure of Squid log file is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file

sub _parse_timestamp {
    my $self = shift;

    # create the timestamp object
    my %t_line = '';

    # fields of interest
    my $date;
    my $text;
    my $r_true = 0;
    my $type;
    my $short;

    # start by initializing the text
    $text = '';

    #print STDERR "PARSING A LINE OF TYPE " . $self->{'r_type'} . "\n";

    # now we need to check the "type" of record
    if ($self->{'r_type'} eq 'account') {

        # content of r_line
        #   0 timezone_policy
        #  1 fullname
        #  2 country
        #   3 given_displayname
        #  4 lastonline_timestamp
        #  5 skypename
        $type = 'Account Information';

        $text .= $self->{'r_line'}->{'fullname'} . ' (' . $self->{'r_line'}->{'skypename'} . ') ';
        $text .= '(display name: ' . $self->{'r_line'}->{'given_displayname'} . ') '
          unless $self->{'r_line'}->{'given_displayname'} eq '';
        $text .= ' last logon to Skype ';
        $text .= '[timezone policy: ' . $self->{'r_line'}->{'timezone_policy'} . '] '
          unless $self->{'r_line'}->{'timezone_policy'} eq '';
        $text .= '<country: ' . $self->{'r_line'}->{'country'} . '> '
          unless $self->{'r_line'}->{'country'} eq '';

        $short =
            $self->{'r_line'}->{'fullname'} . ' ('
          . $self->{'r_line'}->{'skypename'}
          . ') last logged on';

        $date = $self->{'r_line'}->{'lastonline_timestamp'};

        # indicate that we have a valid type
        $r_true = 1;
    }
    elsif ($self->{'r_type'} eq 'chat') {

        # content of r_line
        #  Chats.friendlyname
        #  Chats.dialog_partner
        #  Chats.timestamp
        #  Messages.author
        #  Messages.from_dispname
        #  Messages.body_xml
        #  Messages.timestamp
        #  Messages.dialog_partner
        $type = 'Chat Sent';

        # lets save all dialog_partners and their friendly name (for lookup)
        $self->{'friendlynames'}->{ $self->{'r_line'}->{'author'} } =
          $self->{'r_line'}->{'from_dispname'}
          unless exists $self->{'friendlyname'}->{ $self->{'r_line'}->{'author'} };

        # hver sendir "Messages.author"
        # (? er thad eg, eda hinn?)
        # Messages.dialog_partner (stutta nafnid)

        #my ($in,$b) = split( /\//, $self->{'r_line'}->{'name'} );
        #my ($other,$msg) = split( /\|/, $self->{'r_line'}->{'friendlyname'});
        #$other .= ' (' . $self->{'r_line'}->{'dialog_partner'} . ')';

        # substite multiple spaces for one single
        #$other =~ s/\s+/ /g;

        #my ($out,$c) = split( /;/, $b );
        # remove the first character out

        #printf STDERR "[BEFORE] in <%s> out <%s> [%s]\n",$in,$out,$self->{'r_line'}->{'name'};
        #$in =~ s/[\$#]//;
        #$out =~ s/[\$#]//;
        #printf STDERR "[AFTER] in <%s> out <%s> [%s]\n",$in,$out,$self->{'r_line'}->{'name'};

        # check the directionality of the conversation
        #if( $in eq $self->{'account'} )
        #{
        #  # the user itself is the in (the one talking)
        #  $text .= 'MSG written to ' . $other . ': ';
        #}
        #else
        #{
        # the user itself is the out (the receiver)
        #  $text .= 'MSG from ' . $other . ': ';
        #}

        if ($self->{'r_line'}->{'author'} eq $self->{'account'}) {

            # then the user is the one talking
            $text .= 'MSG written to';
            $text .= ' ' . $self->{'friendlynames'}->{ $self->{'r_line'}->{'dialog_partner'} }
              if exists $self->{'friendlynames'}->{ $self->{'r_line'}->{'dialog_partner'} };
            $text .= ' (' . $self->{'r_line'}->{'dialog_partner'} . ')';
        }
        else {

            # then someone is talking to the user
            $text .=
                'MSG from '
              . $self->{'r_line'}->{'from_dispname'} . ' ('
              . $self->{'r_line'}->{'author'} . ')';
        }

        #  Chats.friendlyname
        #  Chats.dialog_partner
        #  Chats.timestamp
        #  Messages.author
        #  Messages.from_dispname
        #  Messages.body_xml
        #  Messages.timestamp
        #  Messages.dialog_partner

        # the shorter description ends here
        $short = $text;
        $short =~ s/\n//g;
        $short =~ s/\r//g;

        # add the content to the text
        $text .= ': ' . $self->{'r_line'}->{'body_xml'};

        # "fix the text"
        # $text =~ .... # need to remove smiley stuff and replace with something shorter

        # construct the text
        $text =~ s/\n//g;
        $text =~ s/\r//g;

        #

        #print STDERR "R_LINE\n";
        #foreach ( keys %{$self->{'r_line'}} )
        #{
        #  print STDERR "\t$_ => " . $self->{'r_line'}->{$_} . "\n";
        #}

        # the timestamp
        $date = $self->{'r_line'}->{'timestamp'};

        # indicate that we have a valid type
        $r_true = 1;

    }

    # content of array t_line ([optional])
    # %t_line {        #       time
    #               index
    #                       value
    #                       type
    #                       legacy
    #       desc
    #       short
    #       source
    #       sourcetype
    #       version
    #       [notes]
    #       extra
    #               [filename]
    #               [md5]
    #               [mode]
    #               [host]
    #               [user]
    #               [url]
    #               [size]
    #               [...]
    # }

    # create the t_line variable
    %t_line = (
        'time'       => { 0 => { 'value' => $date, 'type' => $type, 'legacy' => 15 } },
        'desc'       => $text,
        'short'      => $short,
        'source'     => 'HIST',
        'sourcetype' => 'Skype History',
        'version'    => 2,
        'extra' => { 'user' => $self->{"fullname"} . ' (' . $self->{'account'} . ')' }
              ) if $r_true;

    %t_line = '' unless $r_true;

    return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "
This plugin parses the content of the History SQL Lite database file that contains
all the information about browser history in Google's Chrome browser.

The History file is usually found at the following location:
  [linux] /home/USER/.config/google-chrome/Default/History
  [linux] /home/USER/.config/chrome/Default/History
  [win 7/vista] C:\\Users\\\[USERNAME\]\\AppData\\Local\\Google\\Chrome\\
  [win xp] C:\\Documents and Settings\\\[USERNAME\]\\Local Settings\\Application Data\\Google\\Chrome\\

There are two options to this script
  -u USERNAME
  -h HOSTNAME
Which is used to define the username of the user that ownes the history file or the host name of the machine in question\n";

}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $temp;
    my $magic = 'SQLite format 3';
    my $self  = shift;
    my $vsth;

    # we assume that the file is not a SQLite database.
    $return{'success'} = 0;
    $return{'msg'}     = 'unknown';

    return \%return unless -f ${ $self->{'name'} };

    # read the first few bits, see if it matches signature
    for (my $i = 0; $i < 15; $i++) {
        seek($self->{'file'}, $i, 0);
        read($self->{'file'}, $temp, 1);
        $line .= $temp;
    }

    # check if the line indicates a real sqlite database (version 3)
    if ($line ne $magic) {
        $return{'success'} = 0;
        $return{'msg'}     = "Wrong magic value.  Is this really a sqlite database?\n";

        return \%return;
    }

    # we know that this is a SQLite database, but is it a Skype one?
    # start by checking if we have a database journal as well
    my $tmp_path = '';
    if (-f ${ $self->{'name'} } . "-journal") {
        eval {
            # create a new variable to store the temp location
            my $rand_int = int(rand(100));
            $tmp_path = '/tmp/tmp_ch.' . $rand_int . 'v.db';

            # we need to copy the file to a temp location and start again
            copy(${ $self->{'name'} }, $tmp_path) || ($return{'success'} = 0);
            copy(${ $self->{'name'} } . "-journal", $tmp_path . "-journal")
              || ($return{'success'} = 0);

            ${ $self->{'name'} } = $tmp_path;
            $self->{'db_lock'} = 1;    # indicate that we need to delete the lock file
        };
        if ($@) {
            $return{'success'} = 0;
            $return{'msg'} =
              'Database is locked and unable to copy to a temporary location (' . $tmp_path . ')';
        }
    }

    # assume we don't have the correct DB structure
    my $skype_db = 0;

    eval {
        # connect to the database
        $self->{'vdb'} = DBI->connect("dbi:SQLite:dbname=" . ${ $self->{'name'} }, "", "")
          or ($skype_db = 1);

        if ($skype_db) {
            $return{'success'} = 0;
            $return{'msg'}     = 'Unable to connect to the database';
            return \%return;
        }

        # get a list of all available tables
        $vsth =
          $self->{'vdb'}->prepare(
            "SELECT skypeout_precision,chat_policy,nr_of_other_instances,skypename,fullname FROM Accounts"
          ) or ($skype_db = 0);

        # execute the query
        my $res = $vsth->execute();

        # check if we have a moz_places table
        @words = $vsth->fetchrow_array();

        $self->{'account'}  = $words[3];
        $self->{'fullname'} = $words[4];

        $skype_db = 1 unless $self->{'account'} eq '';

        # check if temp is set
        if ($skype_db) {
            # now we have a Skype history SQLite database
            $return{'success'} = 1;
            $return{'msg'}     = 'Success';
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'This is not a Skype SQLite database';
        }

        # disconnect from the database
        $vsth->finish;
        undef $vsth;
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'} =
          'Database error ocurred, making verification not possible.  The error message is: '
          . $@;
    }

    return \%return;
}

1;
