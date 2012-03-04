#################################################################################################
#               Log2Timeline
#################################################################################################
#
# Author: Kristinn Gudjonsson
# Version : 0.4
# Date : 10/03/12
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

=pod

=head1 NAME

Log2Timeline - The main engine of log2timeline and the API to interface with. 

=head1 DESCRIPTION

This is the main engine of the tool B<log2timeline>.  This file or engine serves as the communicator
between different parts of the tool.  This is the API that the front-end talks to, and the
engine that iniates both the input and output modules as well as to control the flow of them.
 
So this is the bread and butter of log2timeline so to speak and the library that can be imported
into any tool that wishes to implement a front-end for the tool. And this documentation should
serve as a guideline into how to use the API. If the intention is to develop a new front-end or
a tool that interacts with the engine, either consult this manual, the tool's wiki (
https://code.google.com/p/log2timeline/) or examine the example front-end found inside the dev/
folder from the source tarball.

=head1 SYNOPSIS

  use constant FALSE => 0;
  use constant TRUE => 1;

  # create a new instance of log2timeline
  my $l = Log2Timeline->new( 
    'file' => '.',
    'recursive' => FALSE,
    'input' => 'all',
    'output' => 'csv',
    'time_zone' => 'local',
    'offset' => FALSE,
    'exclusions' => '',
    'text' => '',
    'debug' => FALSE,
    'digest' => FALSE,
    'quick' => FALSE,
    'raw' => FALSE,
    'hostname' => '',
    'preprocess' => 0,
  );
    
  # check if there is a new version available
  print $l->check_upgrade;

  # get the current version number of the tool
  print $l->version;
  
  # get the help text from an input module
  print $l->get_help_in( 'recycler' ); 

  # get the help text from an output module
  print $l->get_help_out( 'csv' ); 

  # change some of the tools settings
  $l->set( 'recursive' => 'yes' );

  # get a list of all the available input modules and lists
  $l->get_inputs;

  # get a list of all the available output modules
  $l->get_outputs;

  # start parsing through the files, gathering timestamps
  $l->start;

  # get a list of all the available timezones
  $l->get_timezone_list;

  # get the currently set timezone
  $l->get_timezone;

=head1 METHODS

This documentation contains a list and description of both public and private methods.
All private methods start with an underscore character (_) and should not be used or called
by front-ends or other tools interacting with the API.

All other methods (excluding private) are considered to be part of the API and can be used
or called by various front-ends.

=cut

package Log2Timeline;
use strict;

use LWP::UserAgent;        # to get the version number from the web
use DateTime::TimeZone;    # for time zones,
use Log2t::Common;         # common shared methods in the framework
use Digest::MD5;           # for MD5 sum calculation
use Pod::Usage;
use DateTime;              # for local time zone detection

# the version variable
use vars qw($VERSION);

# define some constants
use constant TRUE  => 1;
use constant FALSE => 0;

# define all variables used in the script
$VERSION = Log2t::Common::get_version;

=head2 C<new>

The constructor, a very simple one, just returns the value of the secondary constructor.
When a new Log2Timeline object is created it can be created without any parameters, the tool
will simply accept them all as the default value.

IF however, there is a need to overwrite some of the default behavior of the tool, such as to
instruct it to parse another file than the current directory using the local timezone of the machine,
etc. then there are two options. Either to use the parameters to the constructor to define the options
or to use the I<set> sub routine to change a value of a parameter.

Since this constructor only calls a secondary one, please refer to the description of the C<_new>
to get a more detailed description of what is done in this phase.

=head3 Args:

=head4 A hash that defines the parameters and their values. A key and a value, where the key is
the name of the variable needed to be changed from the default one and the value is the new value
of that particular variable.

=head3 Returns:

=head4 An instance of this module.

=cut

sub new() {
    my $class = shift;

    return $class->_new(@_);
}

=head2 C<_new>

The constructor of the tool does not really do anything except to call the private constructor
(this sub routine) and return the value that this sub routine returns.

This routine takes the hash value that is passed to the constructor as a parameter and sets up
all the values of the needed variables in the tool. There are some values that need to be set
for the tool to properly operate, such as the path to the file/directory that needs to be parsed,
the name(s)/list of input modules to load up, time zone of the image and the output, etc.

This routine takes care of assigning values to each of these variables. It compares the hash
that is sent to the routine as a parameter and checks if it recognizes the variable. If it does
it will assign the value that is passed to it, otherwise it will assign it to the default value
that is hardcoded into this sub routine. This means that no values need to be sent to the engine
in order for it to work, it is only necessary to define those that need to be changed from the
default values (listed below).

The variables that the sub routine recognizes are (default values inside brackets []):

=over4

=item B<file>:

The path to the directory/file to be parsed/examined.

=item B<recursive>:

Boolean value (0/1) that indicates if we should use recursive through a mount
point/directory [0/FALSE]

=item B<input>:

String, containg a list of all input modules (comma separated) that
should be loaded. Names can be either a name of a module or a list file, and it can also
be negated with a - sign, indicating that module should be omitted from being loaded. [all]

=item B<output>:

String containing the name of the output module used for output. [csv]

=item B<time_zone>:

String containing the time zone of the image/file that needs to be parsed.
The string can be of any value that the DateTime library supports with the addition of 'local' and 'list'.
'local' will use the local timezone of the computer the tool is run from and 'list' will make the engine
build a list of all available time zones and print them out. [local]

=item B<out_time_zone>:

String containing the time zone that is printed in the output. If the investigator
would like all the output in the same time zone, irrelevant of the input time zone then that can be defined
here. [defaults to the same value as time_zone]

=item B<offset>:

The time on any given computer can be vastly different from a correct clock, which is essential
to correct if the offset to the real clock is known and timestamps from more than one system are being correlated.
This option provides a way to do that. This is a string value or an integer value. If it is an int, then it represents
the number of seconds the clock differs (can be prepended with a - sign indicating a negative difference). It can also
be a string of the form (regular expression) "^-?\d+[hms]?$", whereas 1h means exactly one hour difference, (h = hour,
m = minute, s = second).

=item B<exclusions>:

A string containg a list of exclusions (comma separated). Sometimes the tool does fail (ohh
yes that has actually happened) and fixing that bug is not trivial/done in time/no time to wait. Or that you simply
do not want to include certain files in the timeline then this list can be used. It is a comma separated list of
strings that are used in regular expressions for exclusions (so do not put something like 'a' in there since that
will exclude all files that have the character a somewhere in the path). [empty]

=item B<text>:

A string that will be prepended to every path in the output. If the tool is run with the text
variable set to 'C:' that text will be prepended to every path printed out in the tool. [empty]

=item B<temp>:

A string that contains the path to a temporary directory. The tool sometimes needs to write files
to a temporary directory, this occurs for instance when dealing with locked SQLite databases and possible other
scenarios. Therefore the tool needs ready access to a temporary directory where it can write data. Different
OS's have their default directories, such as the /tmp one in *NIX. The tool does attempt to detect this directory,
but for various reasons it may be desired to overwrite the location of it. ['']

=item B<debug>:

An integer indicating the debug level of the tool. There are currently three level observed:

0 = no debug

1 = debug information turned on.

2 = excessive debug information turned on.

=item B<digest>:

A boolean (0/1) that indicates whether or not we should calculate a MD5 hash for every file
to include as an attribute. N.b. this increases the time it takes the tool to complete by considerable amount.
[FALSE]

=item B<quick>:

Boolean value (0/1). One of the bottlenecks of this tool are the verification of each and every 
file passed to the
tool, making the verification process extremely important to be quick and accurate. However, sometimes the tests
that are made might be too slow/accurate and in order to make it possible to create less accurate yet quicker test
this option is available. Some input modules (although not nearly all of them) may support this option that skips
the more detailed tests and accepts more rudementary validation that a file is what it says it is. [FALSE]

=item B<log_file>:

The file that the tool writes it's output to. [STDOUT]

=item B<raw>:

A boolean (0/1) that flags whether or not the tool uses the output
mechanism that the output modules provide. If this is set to false the tool will operate
as usual, but if true the tool will return the RAW timestamp object instead of a formatted
one, as is done in the case of an output module being used. [FALSE]

=item B<append>:

A boolean value (0/1) that indicates if we want to append to the output
file or to overwrite it. [FALSE]

=item B<detailed_time>:

Boolean (0/1) This is a bit of a misnamer. However, some input modules
to tend to give excessive details in its message/description and even provide additional timetamps
that may or may not be pertinent in every case. This option was added to the tool so that these
perhaps too verbose messages/details wouldn't be introduced into the tool unless wanted/needed.
This means that $FN timestamps are skipped in the $MFT module, loaded drivers are not printed in
the prefetch one, etc. [FALSE]

=item B<hostname>:

A string that contains the hostname of the image/host the files are
extracted from. Some input modules have the capability to extract the hostname, as does
some pre-processors. This variable can however be set to override that and to make sure
the hostname is printed on every event. [unknown]

=item B<preprocess>:

A boolean (0/1) that defines if we should run pre-processors before
the start of the run. [FALSE]

=back

When all values have been assigned the routine will go over each assigned variable and call
a verification routine on them to verify that the variable is valid and that the supplied
value of it is also valid.

When all this is done the routine will assign some other values that are used by the module,
such as the OS of the computer using the tool, etc. It will also assign the value of 1 (TRUE)
to the variable is_valid, indicating that we have properly set up the module and that this
instance is a valid instance of Log2Timeline.

=cut

sub _new() {
    my $class = shift;

    # the arguments to the constructor
    my %c = @_;

    # go over the default values and set the variables that are unset
    $c{'file'} = '.' unless exists $c{'file'};    # the file or directory to be parsed
    $c{'recursive'} = FALSE
      unless exists $c{'recursive'};    # is this is a single file/dir or a recursive search
    $c{'input'} = 'all'
      unless exists $c{'input'};        # use all input modules or single/list/selection/exclude
    $c{'output'} = 'csv' unless exists $c{'output'};    # the name of the output module
    $c{'time_zone'} = 'local'
      unless exists $c{'time_zone'};    # the timezone of the files the tool is about to read
    $c{'out_time_zone'} = $c{'time_zone'}
      unless exists $c{'out_time_zone'};    # the timezone of the output
    $c{'offset'} = 0
      unless exists $c{'offset'
          };    # the time offset, that is the if the clock is incorrect on the suspect system
    $c{'exclusions'} = ''
      unless
        exists $c{'exclusions'}; # the files/patterns that the tool excludes in it's recursive check
    $c{'text'} = '' unless exists $c{'text'};    # a small text to include in each line
    $c{'temp'} = ''
      unless
        exists $c{
              'temp'}; # the temporary directory to use (some modules use a temp dir to store files)
    $c{'debug'} = FALSE
      unless exists $c{'debug'};    # whether debug information should be turned on or off
    $c{'digest'} = FALSE
      unless exists $c{'digest'
          };    # indicates that we would like to calculate MD5sums for each file (extremely slow)
    $c{'quick'} = FALSE
      unless
        exists $c{'quick'};    # enable quick detection mode (might miss some files, but is quicker)
    $c{'log_file'} = 'STDOUT'
      unless
        exists $c{'log_file'};    # the file that we are writing our events to (defaults to STDOUT)
    $c{'raw'} = FALSE
      unless exists $c{'raw'
          };    # indicates that we would like to skip the output file mechanism and just return the
                # timestamp object directly, making it possible to create your own output mechanism
    $c{'append'} = FALSE
      unless exists $c{'append'
          };    # indicates that we are appending to the output file (instead of creating a new one)
    $c{'detailed_time'} = FALSE
      unless exists $c{'detailed_time'
          }; # indicates that we want $FN times added to the MFT parsing (only applicable when MFT is parsed)
    $c{'hostname'} = 'unknown'
      unless exists $c{'hostname'};    # add information about the hostname to the fields
    $c{'preprocess'} = FALSE
      unless exists $c{'preprocess'};    # do we want to call the preprocessing modules or not

    # and now to bless the self class
    my $self = bless {}, $class;

    # now to go over all the variables in the %c and assign them to self
    # BUT not before verifying them (and stopping the process if the verification fails)
    if ($self->_verify('file', $c{'file'})) {
        $self->{'file'}      = $c{'file'};
        $self->{'file_orig'} = $c{'file'};
    }
    else {

        # a parameter to the tool was not verified, hence stop everything right now...
        printf STDERR "[Log2Timeline] File does not exist, %20s\n", $c{'file'};
        return 0;
    }

    # set the separator
    if ($self->{'os'} =~ m/MSWin/) {
        $self->{'sep'} = '\\';
    }
    else {
        $self->{'sep'} = '/';
    }

    # check debug level
    print STDERR "[LOG2T] Reading configuration:\n" if $self->{'debug'};

    # set a counter of parsed objects to zero
    $self->{'counter'} = 0;

    # indicate that we haven't loaded the output module
    $self->{'output_loaded'} = 0;

    # get the library directory
    $self->{'lib_dir'} = Log2t::Common::get_directory();

    # go through the rest of the keys to verify the values
    foreach (keys %c) {
        print STDERR "\t$_\n" if $self->{'debug'};

        next if $_ eq 'file';    # already verified

        # verify the rest of the variables passed to the tool
        if ($self->_verify($_, $c{$_})) {

            # we were able to verify the value, so assign it to the class
            $self->{$_} = $c{$_};
        }
        else {
            printf STDERR "[Log2Timeline] Error, value %s not valid (%s)\n", $_, $c{$_};
            return 0;
        }
    }

    # to include a validation entry
    $self->{'valid'} = 1;

    # detect the OS
    $self->{'os'} = $^O;

    # now we should be ready for our next step
    return $self;
}

=head2 C<is_valid>

A simple subroutine that checks if the variable valid is set or not

=head3 Returns:

=head4 An integer, 1 if this is a valid l2t instance (self->{'valid'} is set), otherwise 0.

=cut

sub is_valid() {
    my $self = shift;

    return 1 if $self->{'valid'};

    return 0;
}

=head2 C<_run_preprocess>

I<A private method (not part of the public API).>

The notion of a pre-processor is something that is run prior to the real execution of the tool
in order to collect information from the image. Each pre-processor can then either choose to simply
output the result of this finding or save it in the class variable that can then be used by other
input/output modules to give more context around events.

This routine starts by finding all the available modules that are available in the 
pre-processing directory.  Then it will run each one of those to gather the necessary information
and update the settings of the tool.

=cut

sub _run_preprocess() {
    my $self = shift;
    my $module;    # the variable that stores the module

    # go through the library file
    opendir(PD, $self->{'lib_dir'} . $self->{'sep'} . 'Log2t' . $self->{'sep'} . 'PreProc');
    my @dir_content = grep { /\.pm$/ } readdir(PD);
    closedir(PD);

    # now to load each one of them
    foreach (@dir_content) {

        # build the module (remove the .pm stuff)
        $module = $_;
        $module =~ s/\.pm$//;
        $module = 'Log2t::PreProc::' . $module;

        print STDERR "[PRE PROCESSING] Runnin pre-processing module $module ($_)\n"
          if $self->{'debug'};
        eval {

            # load the library up
            require $self->{'lib_dir'}
              . $self->{'sep'} . 'Log2t'
              . $self->{'sep'}
              . 'PreProc'
              . $self->{'sep'}
              . $_;
        };
        if ($@) {
            pod2usage(
                      {
                        -message => "Unable to load module $module. Reason given: $@",
                        -verbose => 1,
                        -exitval => 61
                      }
                     );

        }

        # and now to load the preprocessing
        eval {

            # retrieve the information
            $module->get_info($self)
              or print STDERR "[PreProcessing] Unable to retrieve information from $module\n";
        };
        if ($@) {
            pod2usage(
                {
                   -message =>
                     "Unable to retrieve pre-processing information from module $module. Error msg: $@",
                   -verbose => 1,
                   -exitval => 62
                }
            );

        }
    }
}

=head2 C<_build_exclusions>

I<A private method (not part of the public API).>

A simple routine that examines the exclusion list passed to the tool and converts it into a hash
The exclusion list is a string list, separated with commas (,), containing file names or parts of filenames
that should be excluded from the recursive scanner.

The routine simply reads the class variable 'exclusions' and builds a hash called 'exclude_list'
that contains all the patterns found in the exclusion list.

=head3 Returns:

=head4 An integer that inticates whether or not the exclusion building has been successful.

=cut

sub _build_exclusions() {
    my $self = shift;

    # temporary variables
    my @a;
    my %b;

    # split the string
    @a = split(/,/, $self->{'exclusions'});

    # create the hash
    my $i = 0;
    foreach (@a) {

        # check the validity of the exclusion (normal ASCII and numbers only)
        next unless /^[a-zA-Z@0-9_\-]$/;
        print STDERR "Pattern not excluded: '" . $_ . "'\n" unless /^[a-zA-Z@0-9_\-]$/;

        # assign the exclusion to the list
        $b{ $i++ } = $_;
    }

    # and now to put the exclusion list into the self variable, or into our class
    $self->{'exclude_list'} = \%b;

    return 1;
}

=head2 C<version>

A very simple routine that only returns the current version of the tool.

=head3 Returns:

=head4 A string that contains the version of the tool.

=cut
sub version() {
    return $VERSION;
}

=head2 C<_set_timezone>

I<A private method (not part of the public API).>

This routine is used to check if a string representing a timezone is a valid
timezone that is accepted by the DateTime library.

Since there are potentially two time zones defined by the end user, both the one
of the suspect system/files and of the desired output there is a switch indicating
which one we are testing. There is no difference between the two tests, this switch
was simply introduced to make debugging information more concise, that is the difference
is simply in the text used in the debug dialog.

The test that is performed is simply to load the DateTime library with the supplied
timezone. If it successfully loads up it is considered to be a valid timezone string.

If the timezone that was selected is 'local' then the extracted name of said timezone
is pulled from the DateTime object created (all the 'local' magic occurs within the
DateTime library).

It is possible to define a long name for the timezone (e.g 'Australia/Sydney') so the
DateTime library is checked to see if there is a short name for that particular timezone,
and if so that is also returned (and used in the output instead of the longer one).

=head3 Args:

=head4 tz_test: A string of the timezone supplied to the tool and needs to be verified
before being used.

=head4 tz_mode: Boolean variable that defines if we are testing an input or output timezone.

=head3 Returns:

=head4 A list containing two variables, tz_ret a string representing the timezone (might be long)
and a shorter version of that timezone name.

=cut
sub _set_timezone($$$) {
    my $self     = shift;
    my $tz_test  = shift;
    my $tz_mode  = shift;
    my $tz_ret   = '';
    my $tz_short = '';

    my $tz_text = $tz_mode ? 'host' : 'output';

    print STDERR "[LOG2T] Setting $tz_text timezone (", $tz_test, ")\n" if $self->{'debug'};

    # check the timezone settings
    eval {
        print STDERR "[LOG2TIMELINE] Testing $tz_text time zone ", $tz_test, "\n"
          if $self->{'debug'};
        #TODO (kiddi 03/03/2012): Potential security vulnerability with the DateTime library, directly feeding
        #input from user into a third party library, perhaps change this!!!!
        $self->{'time_object'} = DateTime::TimeZone->new('name' => $tz_test);
    };
    if ($@) {
        pod2usage(
                  {
                    -message => "Timezone [" . $tz_test . "] is not a valid timezone",
                    -verbose => 1,
                    -exitval => 45
                  }
                 );

        return 0;
    }

    # check the timezone
    if ($tz_test eq 'local') {
        eval {
                print STDERR "Local timezone is: "
              . $self->{'time_object'}->name . ' ('
              . $self->{'time_object'}->short_name_for_datetime(DateTime->now()) . ")\n";
            $tz_short = $self->{'time_object'}->short_name_for_datetime(DateTime->now());
            $tz_ret   = $self->{'time_object'}->name;
        };
        if ($@) {
            my $temp_msg =
              "[LOG2T] I'm sorry but the tool was unable to determine your local time zone. Please consider running the tool again using another -z option.\n";
            $temp_msg .= "The error message was: $@\n" if $self->{debug};

            pod2usage(
                      {
                        -message => $temp_msg,
                        -verbose => 1,
                        -exitval => 46
                      }
                     );
        }
    }
    else {

        # if we do not use local, then we set it to the same value as the "normal" one
        $tz_short = $tz_test;
        $tz_ret   = $tz_test;
    }

    return ($tz_ret, $tz_short);
}

=head2 C<_verify>

I<A private method (not part of the public API).>

Since we are accepting values from the user of the tool, or from a front-end that cannot
be trusted we need to validate that each attribute is correctly formed. This is not just
as an attempt to verify user inputted data for security purposes, this is also put here
to prevent the tool from crashing in later stages due to a bug in one of the parameters.

For each attribute/parameter of the tool that can be defined through the API it's value
has to be validated. An attribute is not assigned a value unless this validation returns
a true value.

The validation can be very simple, or comprehensive, depending on several factors (one
being not completing the implementation).

The routine has a list of all accepted attributes, and if one is passed to the tool
that the validation routine does not recognize it is deemed as an invalid attribute
and therefore not saved/assigned.

=head3 Args:

=head4 attr: A string containing the name of the attribute that needs to be validated.

=head4 val: The value of said attribute. 

=head3 Returns:

=head4 A boolean value, 0 if the attribute was not valid, 1 if it was deemed valid.

=cut
sub _verify() {
    my $self = shift;
    my $attr = shift;
    my $val  = shift;

    if ($attr eq 'file') {
        print STDERR "[Log2timeline] File/dir does not exist ($val)\n" unless (-f $val or -d $val);
        return 1 if (-f $val or -d $val);

        return 0;
    }
    elsif (   $attr eq 'recursive'
           or $attr eq 'digest'
           or $attr eq 'quick'
           or $attr eq 'raw'
           or $attr eq 'preprocess'
           or $attr eq 'append')
    {
        return 1 if ($val =~ m/^[01]$/);

        print STDERR "[Log2timeline] Parameter [$attr] not correctly formed\n";
        return 0;
    }
    elsif ($attr eq 'debug') {
        return 1 if ($val ge 0 and $val le 4);

        return 0;
    }
    elsif ($attr eq 'detailed_time') {
        return 1 if ($val == TRUE or $val == FALSE);

        return 0;
    }
    elsif ($attr eq 'text' or $attr eq 'log_file') {

        # check if this is "text" based, with "normal" ASCII chars
        return 1 if $val eq '';
        return 1 if ($val =~ m/^[a-zA-Z0-9_-\s\/\\:\.]+$/);

        print STDERR
          "[Log2timeline] Illegal characters included in the parameter [$attr], please use only a-z,A-Z,0-9,_,-,space,:,.\\,\/\n";
        return 0;
    }
    elsif ($attr eq 'hostname') {

        # check if this is "text" based, with "normal" ASCII chars
        return 1 if $val eq '';
        return 1 if ($val =~ m/^[a-zA-Z0-9_-\s\.]+$/);
        print STDERR
          "[Log2timeline] Illegal characters included in the hostname parameter, only use ASCII characters and numbers (plus - and _).\n";

        return 0;
    }
    elsif ($attr eq 'input') {
        my $mod_returned = $self->_input_exists($val);

# if the return value is false, then the module exists, otherwise the module name that does not exist is returned
        if ($mod_returned) {
            print STDERR
              "[Log2timeline] Input module ($mod_returned) does not exist. Please check the full list of input modules (-f list)\n";
            return 0;
        }
        else {
            return 1;
        }
    }
    elsif ($attr eq 'output') {
        return 1 if $self->_output_exists($val);

        print STDERR
          "[Log2timeline] Output module ($val) does not exist. Please check the full list of output modules (-o list)\n";
        return 0;
    }
    elsif ($attr eq 'time_zone' or $attr eq 'out_time_zone') {

        # TODO do this properly...
        return 1;
    }
    elsif ($attr eq 'temp') {
        return 1 if -d $val;
        return 1 if $val eq '';

        print STDERR
          "[Log2timeline] The temporary directory $val does not exist, please create it beforehand.\n";
        return 0;
    }
    elsif ($attr eq 'offset') {

        # the offset can be in the form:
        #   [-]INT[hms]

        return 1 if $val =~ /^-?\d+[hms]?$/;
        return 1 if int($val) ge 0;

        print STDERR "[Log2timeline] Offset needs to be a number, greater than zero.\n";
        return 0;
    }
    elsif ($attr eq 'exclusions') {
        return 1 if $val eq '';
        return 1 if $val =~ m/^[a-zA-Z@0-9, _-]+$/;

        print STDERR
          "[Log2timeline] Wrong usage of the parameter exclusions, please use only lowercase characters, numbers and possible underscore and minus sign.\n";

        return 0;
    }
    else {
        print STDERR
          "[Log2timeline] Unexpected error occured (as if there are any expected ones). Parameter ($attr) is unknown, so please revise your parameters to the tool.\n";

        # unknown value
        return 0;
    }

    # unable to verify, so it's a no go

    print STDERR
      "[Log2timeline] An even more unexpected error occured (opposite to the expected and normally unexpected errors).  Please revise your usage of the verification routine.\n";
    return 0;
}

=head2 C<get_timezone_list>

This is a simple sub routine that pulls out all names of supported timezones of the DateTime
library and puts them in a list.

Ithen sorts that list alphabetically and surrounds it with a banner that gets returned for
output.

=head3 Returns:

=head4 A string containing a list of all available timezones that the DateTime library supports.

=cut
sub get_timezone_list() {
    my @t_list;
    my @t_sort;

    foreach (DateTime::TimeZone->all_names()) {
        push(@t_list, $_);

    }
    foreach (keys(%{ DateTime::TimeZone->links() })) {
        push(@t_list, $_);
    }

    # let's sort the list
    my @t_sort = sort { $a cmp $b } @t_list;

    # and finally to print
    my $txt = "
-----------------------------------
        TIMEZONE LIST
-----------------------------------\n";
    foreach (@t_sort) {
        $txt .= $_ . "\n";
    }

    return $txt;

}

=head2 C<start>

This is one of the main sub routines, the glue that holds all together.
When all values have been assigned to the module and processing can be started
this is the routine that starts it all.

The routine starts by checking if it should do a recursive search or simply
look at a single file.

It will then invoke various internal/protected sub routines that verify and
load up needed functionality. Examples of the magic that occurs in this
routine are; initiating pre-processing, loading input and output modules,
figuring out what the temporary directory is, calculating the clock offset,
assigning timezones, building exclusions.

When all that preparation is done the routine will either call a function
to parse the file or initiate the recursive scan of a mount point/directory.

=cut
sub start($) {
    my $self = shift;
    my $ver;
    my $ret;

    # start by initiating all needed functions, before proceeding

    # check if we want to run preprocessing modules
    if ($self->{'recursive'} and $self->{'preprocess'}) {

        # we only want to run preprocessing if we are in a recursive mode
        $self->_run_preprocess;
    }

    # set the output timezone
    ($self->{'out_time_zone'}, $self->{'short_out_time_zone'}) =
      $self->_set_timezone($self->{'out_time_zone'}, 1);
    return 0 unless $self->{'out_time_zone'};

    # set the timezone
    ($self->{'time_zone'}, $self->{'short_time_zone'}) =
      $self->_set_timezone($self->{'time_zone'}, 0);
    return 0 unless $self->{'time_zone'};

    # check the offset
    $self->_calc_offset;

    # set the temp directory
    # check if temporary directory has been set
    if ($self->{'temp'} eq '') {
        if ($self->{'os'} eq 'MSWin32') {
            eval { require Win32::API; };
            if ($@) {

                # unable to load the windows api
                $self->{'temp'} = '.';
            }

            eval {

                # to get the location of a temp directory
                my $t = new Win32::API "kernel32", "GetTempPath", qw(NP), 'N';
                my $buffer_size = 256;
                $self->{'temp'} = '';
                my $tdude = ' ' x $buffer_size;
                my $len = $t->Call(length($tdude), $tdude);

                if ($len == 0) {
                    print STDERR "Unable to find a temporary directory\n";
                    $self->{'temp'} = '.';
                }
                elsif ($len > length $tdude) {
                    print STDERR
                      "Buffer for temp directory too small; we need $len bytes. Please adjust the variable \$buffer_size in the code\n";
                }
                else {
                    $self->{'temp'} = substr($tdude, 0, $len);
                }
            };
            if ($@) {
                print STDERR
                  "[Log2timeline] Unable to determine the temporary directory. The tool is now using the current directory, please adjust this using the -t TEMP option.\n";
                print STDERR "[Log2timeline] The error message was: $@\n" if $self->{'debug'};
                $self->{'temp'} = '.';
            }
        }
        else {
            if (-d '/tmp') {
                $self->{'temp'} = '/tmp/';
            }
            else {
                $self->{'temp'} = '.';
            }
        }
    }
    else {

        # temp set, check it out
        $self->{'temp'} = '.' unless -d $self->{'temp'};
    }

    # build exclusion list
    $self->_build_exclusions;

    # load output module
    if ($self->{'raw'}) {
        print STDERR "[LOG2T] Not using any output module\n" if $self->{'debug'};
    }
    else {
        print STDERR "[LOG2T] Using output: ", $self->{'output'}, "\n" if $self->{'debug'};
        $self->_load_output unless $self->{'output_loaded'};

        # set the log file location
        $self->{'out'}->{'log_file'} = $self->{'log_file'};

        # print the output header
        unless ($self->{'append'}) {
            if (!$self->{'out'}->print_header()) {
                pod2usage(
                          {
                            -message => "Problem writing header information to file\n",
                            -verbose => 1,
                            -exitval => 20
                          }
                         );
            }
        }

    }

    # load input module(s)
    print STDERR "[LOG2T] Loading input modules (", $self->{'input'}, ")\n" if $self->{'debug'};
    $self->_load_input;

# make a small additional check to see if we are about to run the tool against an image (run rec+pre()
# if we are, we will check to see if the MFT file is actually callable (and that the mft module is
# loaded)
    if ($self->{'recursive'} and $self->{'preprocess'} and exists $self->{'input_list'}->{'mft'}) {
        print STDERR "[LOG2T| Attempting to directly parse the \$MFT FILE.\n" if $self->{'debug'};
        if (-f $self->{'file'} . $self->{'sep'} . '$MFT') {
            print STDERR "[LOG2T] The \$MFT exists, so it is parsable\n" if $self->{'debug'};
            eval {
                my $temp = $self->{'file'};
                $self->{'file'} = $self->{'file'} . $self->{'sep'} . '$MFT';
                $ret            = $self->_parse_file;
                $self->{'file'} = $temp;
            };
            if ($@) {
                print STDERR "[LOG2T] Unable to parse file, reason given: $@\n";
            }
        }
    }

    # check if recursive
    if ($self->{'recursive'}) {
        print STDERR "[LOG2T] Going through a directory using a recursive scanner \n"
          if $self->{'debug'};
        eval { $ret = $self->_parse_dir if -d $self->{'file'}; };
        if ($@) {
            print STDERR "[LOG2T] Error while parsing: " . $self->{'file'} . " error given: $@\n";
        }
    }
    else {

        # single parsing
        print STDERR "[LOG2t] Parsing a single file.\n" if $self->{'debug'};

        eval {

            # parse the file/directory
            $ret = $self->_parse_file if -f $self->{'file'};
            $ret = $self->_parse_file if -d $self->{'file'};
        };
        if ($@) {
            print STDERR "[LOG2T] Unable to parse file, reason given: $@\n";
        }
    }

    # now we've done all the printing, let's end this up
    unless ($self->{'raw'}) {
        if (!$self->{'out'}->print_footer()) {
            pod2usage(
                      {
                        -message => "Error printing document footer\n",
                        -verbose => 1,
                        -exitval => 20
                      }
                     );
        }
    }

    print STDERR "[LOG2T] Done.\n" if $self->{'debug'};
}

=head2 C<get_out_footer>

This subroutine can be called to retrieve the footer of a output file.

This is designed for a front-end to be able to append to an output file even though
the output file has a footer.

The problem this routine tries to solve is that if a file has already been created to
store the timestamp and that particular format contains a footer, simply appending to it
will not cut it. That will brake the format.

The purpose of this routine is to invoke the desired output module and retrieve the footer
that it will output and return that to the front-end that then can remove the footer from
the previous file before starting to output new data.

=head3 Returns:

=head4 The footer (raw, mostly strings, but could be something else) that the output
module produces.

=cut
sub get_out_footer($) {
    my $self = shift;

    # check if the output is "raw"
    return '' if $self->{'raw'};

    # check if output has been loaded, and if not... let's load it
    $self->_load_output unless $self->{'output_loaded'};

    return $self->{'out'}->get_footer;
}

=head2 C<_parse_dir>

I<A private method (not part of the public API).>

This is the recursive method/routine/scanner of the engine. When the tool encounters a
directory and it is in a recursive mode it will use this recursive method to go through
every possible file in the supplied directory, and if it stumples upon a directory it will
call itself with that directory as the root (and thus a recursive method is born).

It is here that the exclusion list is honored. For each file/directory that is found
within the supplied directory the path is compared to the entries found inside the
exclusion list. If a match is found, that particular file is not tested.

The logic in this method is simple:

=over 4

=item B<1>

List up all files within the supplied directory.

=over 8 

=item B<a>

Check against exclusion list, if not there continue.

=item B<b>

Try to parse (if this is a file or a directory).

=item B<c>

If this is a directory then call self again, this time with the current directory
as the root one.

=back

=item B<2>

Done.

=back 

=head3 Returns:

=head4 An integer with the value of 1 (true) if successful.

=cut
# the recursive parsing
sub _parse_dir($) {
    my $self = shift;
    my @ds;
    my $in = 0;
    my $verify;
    my $f_key;
    my $file;
    my $done;
    my $cc;
    my $start;
    my $end;
    my $error = 0;

    print STDERR "[LOG2T] Parsing directory (recursively) " . $self->{'file'} . "\n"
      if $self->{'debug'};

    # don't want to continue, unless this truly is a directory
    print STDERR "[LOG2T] " . $self->{'file'} . " is not a directory\n" unless -d $self->{'file'};
    return 0 unless -d $self->{'file'};

    # try to open the directory up
    eval { $self->_open_dir or die('unable to open the directory'); };
    if ($@) {
        print STDERR "Unable to open the directory " . $self->{'file'} . ". Error message: $@\n";
        return 0;
    }

    if ($error) {
        print STDERR "Unable to open the directory " . $self->{'file'} . ".\n";
        return 0;
    }

    # read all the files inside it
    @ds =
      map { $self->{'file'} . $self->{'sep'} . $_ } grep { !/^\.{1,2}$/ } readdir($self->{'fh'});
    $self->_close_dir;

    # go through all files
    foreach (@ds) {

        # we don't want to process symbolic links, so test for that
        next unless (-f $_ or -d $_);
        next if -l $_;    # especially skip if we are hitting a symlink

        my $f    = $_;
        my $skip = 0;     # a variable defining if we need to skip over to the next file

        # check if the file is excluded from check
        foreach my $e (keys %{ $self->{'exclude_list'} }) {
            my $a = $self->{'exclude_list'}->{$e};

            if ($f =~ m/$a/) {
                print STDERR
                  "[LOG2T] File [$f] skipped.  It's excluded from checking (filter: $a)\n";
                $skip = 1;
            }
        }
        next if $skip;

        print STDERR "[LOG2T] Now inspecting file: [$_]\n" if $self->{'debug'};
        $done = 0;

        # start a high resolution timer
        #$start = [ Time::HiRes::gettimeofday( ) ];

        # start by checking all format files and see if we can parse file
        $self->{'file'} = $f;
        $self->_parse_file;

        # print the time
        #print STDERR $end, "\t", $_, "\n"; #, "|",$end, "\n";

        # now we need to check if this is a file or a folder
        $self->_parse_dir if -d $f;
    }
    return 1;
}

=head2 C<_parse_file>

I<A private method (not part of the public API).>

KOMINN HINGAD!!

=cut
sub _parse_file() {
    my $self = shift;
    my $t_line;    # the timestamp object
    my $done = 0;  # indicates that we've already parsed the file in question
    my $ver;
    my $in_fail = 0; # indicate whether or not we are successful in the initialization of the module

    return 0 unless (-f $self->{'file'} or -d $self->{'file'});

    # load the file
    eval {
        if (-f $self->{'file'})
        {
            $in_fail = $self->_open_file;
        }
        elsif (-d $self->{'file'}) {
            $in_fail = $self->_open_dir;
        }
        else {

            # neither file nor a directory, let's fail
            $in_fail = 0;
        }
    };
    if ($@) {
        print STDERR "Error while opening " . $self->{'file'} . ", msg: $@\n";
        return 0;
    }

    # check if the open function failed
    unless ($in_fail) {
        print STDERR "Unable to open " . $self->{'file'} . "\n";
        return 0;
    }

    # set in_fail again to 0
    $in_fail = 0;

    # now to initialize
    foreach my $in_mod (sort _format_sort (keys %{ $self->{'in'} })) {
        next if $done;    # not necessary to go through this if we've already parsed the file

        print STDERR "[LOG2T] Checking against: " . $self->{'formats'}->{$in_mod}->{'name'} . ": "
          if $self->{'debug'} > 1;

        # set the filename and other "changing" variables into the input module
        $self->{'in'}->{$in_mod}->{'file'} = $self->{'fh'};
        $self->{'in'}->{$in_mod}->{'name'} = \$self->{'file'};
        $self->{'out'}->{'name'}           = $self->{'file'};

        # try to verify the file
        $ver = $self->{'in'}->{$in_mod}->verify;

        # rewind the file to the beginning of it
        seek $self->{'fh'}, 0, 0;

        if ($ver->{'success'}) {
            print STDERR "VALIDATED\n" if $self->{'debug'} > 1;
            print STDERR "[LOG2T] Starting to parse file " . $self->{'file'} . "\n"
              if $self->{'debug'};

            # initialize the module
            $self->{'in'}->{$in_mod}->init or $in_fail = 1;

            # check in_fail
            if ($in_fail) {
                print STDERR
                  "[LOG2T] Initialization of the input module failed, unable to parse.\n";
                next;
            }

            # a variable containing the current input module that is parsing the file
            $self->{'cur_in'} = $self->{'formats'}->{$in_mod}->{'name'};

            # two types of timestamp objects are possible
            #  a) One hash containing several timestamp objects
            #  b) A single timestamp object
            if ($self->{'in'}->{$in_mod}->{'multi_line'} == 1) {
                print STDERR
                  "[LOG2T] This file is dealt with on line-by-line basis (traditional LOG file parsing), meaning one timestamp object per line\n"
                  if $self->{'debug'};

                # we have an ascii file, meaning one timestamp per call to get_time
                eval {
                    while ($t_line = $self->{'in'}->{$in_mod}->get_time)
                    {

                        #print STDERR "About to process timestamp object \n" if $self->{'debug'};
                        # process the timestamps (or jump to the next timestamp)
                        next unless $self->_process_timestamp($t_line);

                        #print STDERR "Timestamp processed\n" if $self->{'debug'};

                        if ($self->{'raw'}) {

                            # no further processing  let the MAIN function handle it
                            ::process_output($t_line);
                        }
                        else {

                            # check if we need to print or return the timestamp object
                            if (!$self->{'out'}->print_line($t_line)) {
                                print STDERR "Error printing line ($t_line->{name})\n";
                            }
                        }
                    }
                };
                if ($@) {
                    print STDERR "[Log2Timeline] Error occured while parsing "
                      . $self->{'file'}
                      . " - The processing has died and therefore it will not be further processed.
However the tool will continue running, trying to parse the next file.
The error that got displayed by the tool is:
$@\n";
                }
            }
            else {

                # a binary file where all timestamp objects are returned at once
                print STDERR "[LOG2T] A binary file, only one object is gathered\n"
                  if $self->{'debug'};

                # get all of the timestamp objects, in a single hash
                $t_line = $self->{'in'}->{$in_mod}->get_time;

                # go through each of the timestamp objects
                foreach (keys %{$t_line}) {

                    # process the timestamp, if unable, then move on to the next one
                    next unless $self->_process_timestamp($t_line->{$_});

                    # check if we are returning "raw" or unprinted timestamp object
                    if ($self->{'raw'}) {

                        # no further processing  let the MAIN function handle it
                        ::process_output($t_line->{$_});
                    }
                    else {

                        # now we need to call the output module and print the line using
                        # the print_line routine that is defined in the main function
                        # we call the print_line function in the output module that in turns
                        # calls the function inside the main function
                        if (!$self->{'out'}->print_line($t_line->{$_})) {
                            print STDERR "Error printing line (" . $t_line->{$_}->{name} . ")\n";
                        }
                    }
                }
            }

            print STDERR "[LOG2T] Parsing of file is completed\n" if $self->{'debug'};

            # we've parsed this file, let's move on
            $done = 1;

            # increment the counter for completed files
            $self->{'counter'}++;

            # end the run
            $self->{'in'}->{$in_mod}->end;
        }
        else {
            print STDERR "Not VALID: $ver->{'msg'}\n" if $self->{'debug'};
            print STDERR "File "
              . $self->{'file'}
              . " not VALID ("
              . $self->{'formats'}->{$in_mod}->{'name'} . "): "
              . $ver->{'msg'} . "\n"
              if (!$self->{'recursive'} and scalar(keys %{ $self->{'in'} }) < 2);
        }
    }

    # close the file
    $self->_close_file if -f $self->{'file'};
    $self->_close_dir  if -d $self->{'file'};

    return 1;
}

=head2 C<_process_timestamp>

I<A private method (not part of the public API).>

=cut
sub _process_timestamp() {
    my $self   = shift;
    my $t_line = shift;

    return 0 unless defined $t_line->{'desc'};
    return 0 if $t_line->{'desc'} eq '';

    # fix the \ vs. / problem in the output
    $t_line->{'desc'}  =~ s/\\/\//g;
    $t_line->{'short'} =~ s/\\/\//g;

    if (defined $self->{'text'} and $self->{'text'} ne '') {
        $t_line->{'extra'}->{'path'} = $self->{'text'};
    }

    # add information about the directory passed on to the tool
    $t_line->{'extra'}->{'parse_dir'} = $self->{'file_orig'} if $self->{'recursive'};

    # default value of self->hostname is unknown
    if ($self->{'hostname'} ne 'unknown') {

        # we have a user supplied hostname, use that and overwrite what ever is in this field
        $t_line->{'extra'}->{'host'} = $self->{'hostname'}
          unless defined $t_line->{'extra'}->{'host'};
    }
    else {

        # use the default one of 'unknown' unless it is already assigned in the input module
        $t_line->{'extra'}->{'host'} = 'unknown' unless defined $t_line->{'extra'}->{'host'};
    }

    # add the filename to the t_line
    $t_line->{'extra'}->{'filename'} = $self->{'file'}
      unless defined $t_line->{'extra'}->{'filename'};
    $t_line->{'extra'}->{'format'} = $self->{'cur_in'}
      unless defined $t_line->{'extra'}->{'format'};

    # check the inode value (and fix it if is set to zero)
    $t_line->{'extra'}->{'inode'} = (stat($self->{'file'}))[1]
      unless defined $t_line->{'extra'}->{'inode'};

    # fix the time settings (using time_offset)
    foreach (keys %{ $t_line->{'time'} }) {
        next unless defined $t_line->{'time'}->{$_}->{'value'};

#    if ( $self->{'debug'} )
#    {
#
#      print STDERR "[KD] Defined " . $t_line->{'time'}->{$_}->{'type'} . "\n" if defined $t_line->{'time'}->{$_}->{'value'};
#      print STDERR "[KD] Nuna: " . $t_line->{'time'}->{$_}->{'value'} . ' EFTIR: ';
#    }
        $t_line->{'time'}->{$_}->{'value'} += $self->{'offset'};

        #    print STDERR $t_line->{'time'}->{$_}->{'value'} . "\n" if $self->{'debug'};
    }

    # check to see if we are to calculate MD5 sum of the file
    if ($self->{'digest'}) {

        #    # check if we've already calculated the md5 for this file
        #    if( $last_sum{'file'} eq $self->{'file'} )
        #    {
        #      # no need to re-calculate
        #      $t_line->{'extra'}->{'md5'} = $last_sum{'md5'};
        #    }
        #    else
        #    {
        # we need to calculate a new sum

        # calculate the MD5 sum
        open(TF, '<' . $self->{'file'});
        my $sum = Digest::MD5->new;
        $sum->addfile(*TF);

        $t_line->{'extra'}->{'md5'} = $sum->hexdigest;

        #      # update the last_sum object
        #      $last_sum{'file'} = $file;
        #      $last_sum{'md5'} = $sum->hexdigest;

        close(TF);

        #    }
    }

    return 1;
}

=head2 C<_open_file>


I<A private method (not part of the public API).>

=cut
sub _open_file() {
    my $self = shift;

    open(HF, '<', $self->{'file'}) or return 0;

    $self->{'fh'} = \*HF;

    return 1;
}

=head2 C<_close_file>

I<A private method (not part of the public API).>

=cut
sub _close_file() {
    my $self = shift;

    close(HF);
    $self->{'fh'} = undef;

    return 1;
}

=head2 <_open_dir>

I<A private method (not part of the public API).>

=cut
sub _open_dir() {
    my $self = shift;

    opendir(DH, $self->{'file'}) or return 0;

    $self->{'fh'} = \*DH;

    return 1;
}

=head2 <_close_dir>

I<A private method (not part of the public API).>

=cut
sub _close_dir() {
    my $self = shift;

    closedir(DH);
    $self->{'fh'} = undef;

    return 1;
}

=head2 C<_input_exists>


I<A private method (not part of the public API).>

=cut
sub _input_exists() {
    my $self = shift;
    my $in   = shift;
    my $ret  = 0;       # the default return value
    my ($a, $b);

    # we can be guessing.. so check out if that's the case
    return 0 if $in eq 'all';

    # the list might contain a minus sign, let's remove them all
    $in =~ s/-//g;

    # we might be using several modules
    my @s = split(/,/, $in);

    # go over each one (only done once if just one is passed on)
    foreach (@s) {

        # we do not need further checking if $ret is 0
        next if $ret;

        # set the default values
        $a = 0;
        $b = 0;

        # check if we are about to use a list file
        $a = 1
          if -f $self->{'lib_dir'}
              . $self->{'sep'} . 'Log2t'
              . $self->{'sep'} . 'input'
              . $self->{'sep'}
              . $_ . '.lst';

        # or we are using a single input module
        $b = 1
          if -f $self->{'lib_dir'}
              . $self->{'sep'} . 'Log2t'
              . $self->{'sep'} . 'input'
              . $self->{'sep'}
              . $_ . '.pm';

        # either a or b needs to be true
        $ret = $_ unless ($a or $b);
    }

    return $ret;
}

=head2 C<_output_exists>

I<A private method (not part of the public API).>

=cut
sub _output_exists() {
    my $self = shift;
    my $out  = shift;

    print STDERR "[LOG2T] Testing the existence of ",
        $self->{'lib_dir'}
      . $self->{'sep'} . 'Log2t'
      . $self->{'sep'}
      . 'output'
      . $self->{'sep'}
      . $out . ".pm\n"
      if $self->{'debug'};

    return 1
      if -f $self->{'lib_dir'}
          . $self->{'sep'} . 'Log2t'
          . $self->{'sep'}
          . 'output'
          . $self->{'sep'}
          . $out . '.pm';
    print STDERR "SEPERATOR [" . $self->{'sep'} . "]\n";
    print STDERR $self->{'lib_dir'}
      . $self->{'sep'} . 'Log2t'
      . $self->{'sep'}
      . 'output'
      . $self->{'sep'}
      . $out . '.pm' . "\n";
    return 0;
}

sub get_timezone() {
    my $self = shift;

    return $self->{'time_zone'};
}

=head2 C<_load_input_list>

I<A private method (not part of the public API).>

=cut
sub _load_input_list() {
    my $self = shift;
    my $list = shift;

# the variable can either by a user supplied list (comma separated) or a file called INPUT.lst which lists the input modules that are to be used
# we are reading from a file
    open(LSTFILE,
             $self->{'lib_dir'}
           . $self->{'sep'} . 'Log2t'
           . $self->{'sep'} . 'input'
           . $self->{'sep'}
           . $list . '.lst'
        );
    while (<LSTFILE>) {
        s/\n//;
        $self->{'input_list'}->{$_}++;
    }

    close(LSTFILE);
}

=head2 C<_load_input_module>

I<A private method (not part of the public API).>

# either remove or add a module to the input list
=cut
sub _load_input_module() {
    my $self = shift;
    my $mod  = shift;

    # check for the first letter (if it is - then we use all except the ones listed
    if (substr($mod, 0, 1) eq '-') {

        # remove the -
        $mod = substr($mod, 1);

        # check if the module exists (and remove it from the list if it exists...
        if (  -f $self->{'lib_dir'}
            . $self->{'sep'} . 'Log2t'
            . $self->{'sep'} . 'input'
            . $self->{'sep'}
            . $mod . '.pm')
        {
            print STDERR "[DEBUG] Removing the module $mod.\n"
              if ($self->{'debug'} and defined($self->{'input_list'}->{$mod}));

            delete($self->{'input_list'}->{$mod}) if exists($self->{'input_list'}->{$mod});
        }
        else {
            print STDERR "[DEBUG] Module ($mod) does not exist.\n";
        }

    }
    else {

        # add the module to the list
        if (  -f $self->{'lib_dir'}
            . $self->{'sep'} . 'Log2t'
            . $self->{'sep'} . 'input'
            . $self->{'sep'}
            . $mod . '.pm')
        {
            print STDERR "[DEBUG] Adding the module $mod.\n" if $self->{'debug'};
            $self->{'input_list'}->{$mod}++;
        }
        else {
            print STDERR "[DEBUG] Module ($mod) does not exist.\n" if $self->{'debug'};
        }
    }
}

=head2 C<_load_input>

I<A private method (not part of the public API).>

=cut
sub _load_input() {
    my $self = shift;
    my @dir_content;

    if ($self->{'input'} eq 'all') {

        # we would like to include all available input modules
        opendir(PD,
                    $self->{'lib_dir'}
                  . $self->{'sep'} . 'Log2t'
                  . $self->{'sep'} . 'input'
                  . $self->{'sep'}
               )
          || die(  "Could not open the directory "
                 . $self->{'lib_dir'}
                 . $self->{'sep'} . "Log2t"
                 . $self->{'sep'}
                 . "input \n");
        my @dir_content2 = grep { /\.pm$/ } readdir(PD);

        foreach (@dir_content2) {
            s/\.pm//;
            push(@dir_content, $_);
        }
        closedir(PD);
    }
    else {

        # start by splitting up variables and check them out, one by one
        @dir_content = split(/,/, $self->{'input'});
    }

    # go through each of the modules listed in the input
    foreach (@dir_content) {
        if (  -f $self->{'lib_dir'}
            . $self->{'sep'} . 'Log2t'
            . $self->{'sep'} . 'input'
            . $self->{'sep'}
            . $_ . '.lst')
        {

            #print STDERR "BEFORE\n";
            $self->_load_input_list($_);

            #print STDERR "AFTER\n";
        }
        else {
            $self->_load_input_module($_);
        }
    }

    # now to check if all input module files truly exist
    foreach (keys %{ $self->{'input_list'} }) {
        pod2usage(
                  {
                    -message => 'Input module (' . $_ . ') does not exist.',
                    -verbose => 1,
                    -exitval => 29
                  }
                 )
          unless -f $self->{'lib_dir'}
              . $self->{'sep'} . 'Log2t'
              . $self->{'sep'} . 'input'
              . $self->{'sep'}
              . $_ . '.pm';
    }

    # now to load up all the available input modules
    my @modules_used;
    my $temp;
    foreach (keys %{ $self->{'input_list'} }) {
        $temp = 'Log2t::input::' . $_;

        #$temp =~ s/\.pm//g;

        my $i = $_;

        #$i =~ s/\.pm//g;
        push(@modules_used, $i);    # add the module name to a list

        $self->{'formats'}->{ $i++ } = {
                                         'file' => $_ . '.pm',
                                         'name' => $temp
                                       };
    }

    # load all the modules
    eval {

        # include the format
        foreach (keys %{ $self->{'formats'} }) {
            print STDERR "[LOG2T] Loading module ", $self->{'formats'}->{$_}->{'name'}, "\n"
              if $self->{'debug'};
            require $self->{'lib_dir'}
              . $self->{'sep'} . 'Log2t'
              . $self->{'sep'} . 'input'
              . $self->{'sep'}
              . $self->{'formats'}->{$_}->{'file'};

            # create new instance of the modules
            $self->{'in'}->{$_} = $self->{'formats'}->{$_}->{'name'}->new();

            # check if debug is turned on
            $self->{'in'}->{$_}->{'debug'}         = $self->{'debug'};
            $self->{'in'}->{$_}->{'quick'}         = 1 if $self->{'quick'};
            $self->{'in'}->{$_}->{'tz'}            = $self->{'time_zone'};
            $self->{'in'}->{$_}->{'path'}          = $self->{'text'};
            $self->{'in'}->{$_}->{'detailed_time'} = $self->{'detailed_time'};
            $self->{'in'}->{$_}->{'temp'}          = $self->{'temp'};
            $self->{'in'}->{$_}->{'sep'}           = $self->{'sep'};

            # add the default user browser if the information is available (through pre-processing)
            $self->{'in'}->{$_}->{'defbrowser'} = $self->{'defbrowser'}
              if defined $self->{'defbrowser'};
        }
    };
    if ($@) {
        pod2usage(
                  {
                    -message => "Problem loading input modules.  Error message: $@\n",
                    -verbose => 1,
                    -exitval => 10
                  }
                 );
    }

    return 1;
}

=head2 C<_load_output>

I<A private method (not part of the public API).>

=cut
sub _load_output() {
    my $self = shift;

    print STDERR "Loading output file: " . $self->{output} . "\n";

    eval {
        $self->{'out_mod'} = 'Log2t::output::' . $self->{output};
        require $self->{'lib_dir'}
          . $self->{'sep'} . 'Log2t'
          . $self->{'sep'}
          . 'output'
          . $self->{'sep'}
          . $self->{output} . '.pm';

        # start the constructor
        $self->{'out'} = $self->{'out_mod'}->new;

        # assign some variables to the output module
        $self->{'out'}->{'tz'}        = $self->{'time_zone'};
        $self->{'out'}->{'otz'}       = $self->{'out_time_zone'};
        $self->{'out'}->{'short_tz'}  = $self->{'short_time_zone'};
        $self->{'out'}->{'short_otz'} = $self->{'short_out_time_zone'};
        $self->{'out'}->{'debug'}     = $self->{'debug'};
        $self->{'out'}->{'sep'}       = $self->{'sep'};
    };
    if ($@) {

        # failed to open
        pod2usage(
                  {
                    -message => "Failed to open output file: "
                      . $self->{output}
                      . " . Error message: $@",
                    -verbose => 1,
                    -exitval => 13
                  }
                 );
    }

    # indicate the tool that the output module has already been loaded
    $self->{'output_loaded'} = 1;
    return 1;
}

sub get_inputs() {
    my $text = '';
    $text = Log2t::Common::list_input();
    $text .= Log2t::Common::list_lists();

    return $text;
}

sub get_outputs() {
    return Log2t::Common::list_output();
}

sub check_upgrade() {

    # check the latest version
    my $text;

    # fetch the latest version number on the log2timeline web site
    my $dw = LWP::UserAgent->new(agent => 'log2timeline update browser');

    # set the proxy and timeout
    $dw->timeout(10);
    $dw->env_proxy;

    $text = $dw->get('http://log2timeline.net/VERSION');

    if ($text->is_success) {

        # decode the content
        $text = $text->decoded_content;

        # remove the new line character
        chomp($text);

        # and now we compare the versions
        if ($text eq $VERSION) {
            return
              "This is the latest version of log2timeline (although the nightly build might be newer)";
        }
        elsif ($text > $VERSION) {
            return
              "There is a newer version available.  Current version is $text, and this is version $VERSION
The tool update_log2timeline which is distributed with the tool can be used to update the tool automatically (needs to be run by the user root)";
        }
        else {
            return
              "Your version is newer than that on the main server (current version $text, yours $VERSION)";
        }
    }
    else {
        return
          "[CHECK] Version check unable to complete.  Are you behind a proxy that is not correctly set in the environment PATH and are you connected to the Internet? (or is the log2timeline server possibly not responding?)";
    }

}

=head2 C<_get_module_help>

I<A private method (not part of the public API).>

=cut
sub _get_module_help() {
    my $self         = shift;
    my $check_module = shift;
    my $method       = shift;
    my $text;
    my $in;

    return '' unless $method eq 'input' or $method eq 'output';

    $text = "=" x 80 . "\n";
    $text .= "\t\tModule help - " . $method . " module $check_module\n";
    $text .= "-" x 80 . "\n";

    # one thing to keep in mind that input modules have not been loaded at this time
    # get the help
    if (  -f $self->{'lib_dir'}
        . $self->{'sep'} . 'Log2t'
        . $self->{'sep'}
        . $method
        . $self->{'sep'}
        . $check_module . '.pm')
    {

        # load the module up
        require $self->{'lib_dir'}
          . $self->{'sep'} . 'Log2t'
          . $self->{'sep'}
          . $method
          . $self->{'sep'}
          . $check_module . '.pm';
        $in = 'Log2t::' . $method . '::' . $check_module;

        # load the get_help portion of the module
        $text .= sprintf "%-80s", $in->get_help();
        $text .= "\n";
    }
    else {
        $text = "Unable to locate the module $check_module\n";
    }

    $text .= "=" x 80 . "\n";
    $text .= "\n";
    return $text;
}

sub get_help_in() {
    my $self  = shift;
    my $check = shift;

    return $self->_get_module_help($check, 'input');
}

sub get_help_out() {
    my $self  = shift;
    my $check = shift;

    return $self->_get_module_help($check, 'output');
}

sub set() {
    my $self  = shift;
    my %new_c = @_;

    # go through the %new_c hash and see if we need to update some settings in the $self
    foreach (keys %new_c) {
        if (exists $self->{$_}) {

            # verify before we make a change
            if ($self->_verify($_, $new_c{$_})) {
                $self->{$_} = $new_c{$_};
            }
            else {
                pod2usage(
                          {
                            -message => "Error in parameter ($_ = "
                              . $new_c{$_}
                              . "), please see help file.\n",
                            -verbose => 1,
                            -exitval => 21
                          }
                         );
            }
        }
    }
}

=head2 C<_format_sort>

I<A private method (not part of the public API).>

A sorting 'algorithm' for input modules.

The problem with some of the input modules is that there might be two input modules
that are capable of parsing the same file. And since the tool stops processing each file
when a match is found you might end up parsing a file using a module that is not really
suited to do so.

The most prelevant example is the exif module that is capable of extracting a generic
metadata from vast amount of different types of files. There might be other modules that
are specifically written to parse that particular file, which do a lot better job of
extracting relevant data from it. This routine is therefore written to lower the priority
of these more generic modules so that they do not parse files before the more specific
ones do.

Currently the following modules do have lower priority associated to them:

=over 8

=item B<exif>

=item B<generic_linux>

=back

=cut
sub _format_sort($$) {
    my $self = shift;

    return 1  if $a eq 'exif';
    return -1 if $b eq 'exif';
    return -1 if $a eq 'generic_linux';
    return 1  if $a eq 'generic_linux';

    return $a cmp $b;
}

=head2 C<_calc_offset>

I<A private method (not part of the public API).>

A sub routine that takes the offset value that is given to the API and converts it
into an integer that is used to balance of the timestamps read.

The offset can be one of each values:

+ int: numbers of seconds (eg. 52 or -12)

+ string: An int with appended character indicating the unit of the int. Accepted
values are h, m or s that correspond to hours, minutes and seconds. Examples:
52s or 1h (n.b. it is not possible to use 4h2m1s to represent the time in more granularity,
it is only possible to use one string, making the int option most useful since offset rarely
comes in whole hours.

No arguments are needed since the routine only uses and sets class variables.

=cut
sub _calc_offset() {
    my $self = shift;

    # fix the time offset (if the parameter was set)
    # start by checking out the variable time_offset (possible to use INTh to indicate hours, and INTm to indicate minutes)
    if ($self->{'offset'} =~ m/h$/) {

        # the input is in hours, so modify it to represent seconds

        # modify the offset

        # chop of the last character (the h representing hour)
        chop($self->{'offset'});
        if ($self->{'offset'} =~ m/^-?\d+$/) {

            # now  we've confirmed that we are dealing with a number, let's multiply
            $self->{'offset'} *= 3600;
        }
        else {

            # the time offset is badly formed, not XXXh where XXX is an integer
            print STDERR "Time offset is badly formed\n";
            $self->{'offset'} = 0;
        }

    }

    # check to see if the time offset is appended with m, for minutes
    if ($self->{'offset'} =~ m/m$/) {

        # modify the offset
        chop($self->{'offset'});
        if ($self->{'offset'} =~ m/^-?\d+$/) {
            $self->{'offset'} *= 60;
        }
        else {
            print STDERR "Time offset is badly formed\n";
            $self->{'offset'} = 0;
        }

    }

    # and if someone added s to represent seconds
    if ($self->{'offset'} =~ m/s$/) {

        # just chop off the s for seconds
        chop($self->{'offset'});
    }

    if ($self->{'offset'} != 0) {
        print STDERR "[LOG2T] Offset is " . $self->{'offset'} . "s\n" if $self->{'debug'};
    }
}

1;

__END__

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

=head1 COPYRIGHT

The tool is released under GPL so anyone can contribute to the tool and examine the source code. Copyright 2009-2012.

=head1 SEE ALSO

Documentation for each input module follows the name of Log2t::input::MODULE and for output modules Log2t::output::MODULE

L<log2timeline>, L<Log2t::Time>, L<Log2t::BinRead>, L<Log2t::Common>, L<Log2t::Network>, L<Log2t::Numbers>, L<Log2t::Win>, L<Log2t::WinReg>

=cut

