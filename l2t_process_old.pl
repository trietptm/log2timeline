#!/usr/bin/perl
#################################################################################################
#               l2t_process
#################################################################################################
# This script is a part of the the program log2timeline that is designed to parse a log file,
# any supported log file, and output it in a bodyfile that can be read by supporting software for
# timeline creation.
#
# This script processs the CSV output in a similar fashion as mactime does for the mactime body
# file.
#
# Author: Kristinn Gudjonsson
# Date : 18/05/11
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
use strict;
use DateTime;
use Getopt::Long;    # read parameters
use Pod::Usage;      # for man and help messages
use POSIX;

use vars qw($VERSION);

# define the version number
$VERSION = "0.2";

# define the variables used
my $start_time = time;     # marking the beginning of the tool's run time
my $file       = undef;    # the CSV file
my $debug      = 0;        # debug
my $reverse    = 0;        # format of the date variable
my $line;                  # stores the line being read
my $e;                     # stores an epoch value
my $t_ofs;                 # the offset from UTC to the timezone
my $sep;                   # defines the separator found inside the input file
my $line_counter = 0;      # defines a counter of lines that are to be printed out

# define two variables that are used to define a random number and a small part of the line, to make fields unique
my ($rand_number, $part_of_line);

my $min = undef;           # the epoch time of lower date range
my $max = undef;           # the epoch time of the upper date range
my $zone;                  # definition of the time zone
my $show_help         = 0;        # check if we want to show the help message
my $show_version      = 0;        # check if we want to see the version of the tool
my $keyword_file      = undef;    # talk about a file containing keywords
my $tab_file          = 0;        # indicates that the input file is tab delimited instead of CSV
my @keywords          = undef;    # the keyword list
my $include_timestomp = 0;        # indicate that we do want to include the timestomp
my $exclude_timestomp = 0;        # exclude the inclusion of timestomp activity by default
my $draw_scatter_plot = 0;        # indicate whether or not we would like to draw a scatter plot
my $scatter_file      = undef;    # the file name for the scatter plot files
my %scatter;                      # scatter entries
my $treat_scatter_as_one_slice =
  1;    # the default behaviour of detecting outliers, treating the whole graph as one slice
my $multi_slice    = 0;    # an option to change the "tread_scatter_as_one_slice" option above
my $whitelist_file = ''
  ; # the file that contain whitelisting keywords ("known good") - list of lines to skip in the timeline
my @whitelist;    # the array that contains the whitelisting words

# counters
my %counter = (
      'duplicate' => { 'value' => 0, 'text' => 'Total number of duplicate entries removed' },
      'total'     => { 'value' => 0, 'text' => 'Total number of processed entries' },
      'filter' =>
        { 'value' => 0, 'text' => 'Total number of events that fit into the filter (got printed)' },
      'skip_keyword' =>
        { 'value' => 0, 'text' => 'Total number of events skipped due to keyword filtering' },
      'skip_whitelist' =>
        { 'value' => 0, 'text' => 'Total number of events skipped due to whitelisting' },
);

# skip the ignore case, that is make it sensitive to upper and lowercase letters
Getopt::Long::Configure("no_ignore_case");

# read options
GetOptions(
           "b=s"         => \$file,
           "verbose+"    => \$debug,
           "tab!"        => \$tab_file,
           "y!"          => \$reverse,
           "keyword=s"   => \$keyword_file,
           "whitelist=s" => \$whitelist_file,
           "include!"    => \$include_timestomp,
           "exclude!"    => \$exclude_timestomp,
           "scatter|s=s" => \$draw_scatter_plot,
           "multi"       => \$multi_slice,
           "Version!"    => \$show_version,
           "help!"       => \$show_help
          ) or pod2usage(2);

# check if we are trying to get some help
if ($show_help) {
    pod2usage(1);
    exit 0;
}

if ($show_version) {
    print "l2t_process version: " . $VERSION . " (part of log2timeline)\n";
    exit 0;
}

# some debug information
print STDERR "[DEBUG] Running $0 in debug mode.\n"    if $debug;
print STDERR "[DEBUG] This is a TAB delimited file\n" if ($debug and $tab_file);
print STDERR "[DEBUG] This is a CSV file\n"           if ($debug and !$tab_file);
print STDERR "[DEBUG] Running with reverse dates\n"   if ($debug and $reverse);

# date range
my $range = shift;
my %p_line;        # hash storing the dates that fit the range
my %stomp_line;    # hash storing dates outside range, yet show signs of possible timestomping

print STDERR "[DEBUG] The date range is set as: $range\n" if $debug;

# check if we want to use multiple slices in our calculation of outliers in the dataset
if ($multi_slice and $draw_scatter_plot) {
    $treat_scatter_as_one_slice = 0;
    print STDERR
      "[OUTLIER DETECTION] We are attempting to split up the data set into smaller sections for outlier detection\n";
}

# some simple checks
pod2usage(
          {
            -message => "Unable to load body file [$file].",
            -verbose => 0,
            -exitval => 12
          }
         ) unless -f $file;

# check for the keyword file
if ($keyword_file) {
    print STDERR "Building keyword list...";

    pod2usage(
              {
                -message => "Unable to open keyword file [$keyword_file].",
                -verbose => 0,
                -exitval => 12
              }
             ) unless -f $keyword_file;

    open(KF, $keyword_file);

    while (<KF>) {

        # "fix" the keyword line
        s/\s+//g;     # remove spaces
        s/\s//g;
        s/,/-/g;      # swap commas for dashes
        s/\\/\//g;    # swap \ for / (since all the entries do use / instead of \
        s/\n//g;      # remove newline characters away
        s/\r//g;      # same with the \r (newline)

        # dont want empty lines
        next if /^$/;

        # dont care about comments (lines starting with #)
        next if /^#/;

        # and then to check the keyword itself
        if (/^[a-zA-Z0-9\@_\-\.\/\[\]:=\?]+$/) {
            push(@keywords, lc($_));
        }
        else {
            print STDERR "Current version does not support the following keyword [$_]\n";
        }
    }

    close(KF);

    print STDERR "DONE (" . sprintf("%d", $#keywords + 1) . " keywords loaded)\n";

    if ($debug) {
        my $a = 1;
        print STDERR "Keyword list after cleaning is: \n";
        foreach (@keywords) {
            next if $_ eq '';
            print STDERR "\t[" . $a++ . "] $_\n";
        }
    }
}

# check for the whitelist file
if ($whitelist_file) {
    print STDERR "Building whitelist (known good)...";

    pod2usage(
              {
                -message => "Unable to open whitelist file [$whitelist_file].",
                -verbose => 0,
                -exitval => 12
              }
             ) unless -f $whitelist_file;

    open(WF, $whitelist_file);

    while (<WF>) {

        # "fix" the keyword line
        s/\s+//g;     # remove spaces
        s/\s//g;
        s/,/-/g;      # swap commas for dashes
        s/\\/\//g;    # swap \ for / (since all the entries do use / instead of \
        s/\n//g;      # remove newline characters away
        s/\r//g;      # same with the \r (newline)

        # dont want empty lines
        next if /^$/;

        # dont care about comments (lines starting with #)
        next if /^#/;

        # and then to check the keyword itself
        if (/^[a-zA-Z0-9\@_\-\.\/=]+$/) {
            push(@whitelist, lc($_));
        }
        else {
            print STDERR "Current version does not support the following keyword [$_]\n";
        }
    }

    close(WF);

    print STDERR "DONE (" . sprintf("%d", $#whitelist + 1) . " keywords loaded)\n";

    if ($debug) {
        my $a = 1;
        print STDERR "Whitelist after cleaning is: \n";
        foreach (@whitelist) {
            next if $_ eq '';
            print STDERR "\t[" . $a++ . "] $_\n";
        }
    }
}

if ($draw_scatter_plot) {

    # create the scatter_file variable, "fix" the input
    # we would like to only include ASCII characters and _,
    my @a = split(/\./, $draw_scatter_plot);
    $scatter_file = $a[0];

    # clean the file name
    $scatter_file =~ s/[^a-zA-Z_0-9]//g;

    # check if
    if ($draw_scatter_plot ne $scatter_file) {
        print STDERR "The scatter plot will be saved using file names (variable modified) "
          . $scatter_file
          . ".[dat|cmd|png]\n";
    }
    else {
        print STDERR "The scatter plot will be saved using file names "
          . $scatter_file
          . ".[dat|cmd|png]\n";
    }
}

# the separator is either tab or comma, depending on the variable tab_file
if ($tab_file) {
    $sep = "\t";
}
else {
    $sep = ',';
}

print STDERR "[DEBUG] The separator is '" . $sep . "'\n" if $debug;

# open the file - that is the CSV output file (or the TAB file)
open(FH, $file);

pod2usage(
        {
          -message => "Unable to verify the CSV file, is it really a CSV created by log2timeline?",
          -verbose => 0,
          -exitval => 4
        }
) unless verify();

print STDERR "[DEBUG] File has been verified, it contains the correct structure.\n" if $debug;

# rewind the file
#seek FH, 0, 0;

eval {

    # we know the correct timezone, so let's calculate the difference
    my $temp = DateTime->from_epoch(epoch => time(), 'time_zone' => 'UTC');
    $temp->set_time_zone($zone);
    $t_ofs = $temp->offset();
};
if ($@) {
    print STDERR
      "Error while getting the offset from UTC to the timezone $zone.\nError message: $@\n";
    exit 80;
}

print STDERR
  "[DEBUG] The detected timezone of the file is [$zone], which differs by $t_ofs sec from GMT/UTC.\n"
  if $debug;

# now to calculate the min and max values
# check the range
if ($range eq '') {

    # set the minimum and maximum values to the "extremes" so we catch everything...
    $min = 0;
    $max = 9999999999;
}

# check if we have a range (....)
elsif ($range =~ m/^([0-9\-]+)\.\.([0-9\-]+)$/) {

    # now we got two dates
    eval { $min = calc_min($1); };
    if ($@) {
        pod2usage(
            {
               -message =>
                 "Wrong usage: Date range not correctly formed, should be (mm-dd-yyyy) or range (mm-dd-yyyy..mm-dd-yyyy) - ($@)",
               -verbose => 1,
               -exitval => 13
            }
        );
    }

    eval { $max = calc_max($2); };
    if ($@) {
        pod2usage(
            {
               -message =>
                 "Wrong usage: Date range not correctly formed, should be (mm-dd-yyyy) or range (mm-dd-yyyy..mm-dd-yyyy) - ($@)",
               -verbose => 1,
               -exitval => 14
            }
        );
    }

}

# check if there is only one date (so from then and until the end)
elsif ($range =~ m/^([0-9\-]+)$/) {
    eval { $min = calc_min($range); };
    if ($@) {
        pod2usage(
            {
               -message =>
                 "Wrong usage: Date range not correctly formed, should be (mm-dd-yyyy) or range (mm-dd-yyyy..mm-dd-yyyy) - ($@)",
               -verbose => 1,
               -exitval => 15
            }
        );
    }

    $max = 9999999999;
}

# or if we simply have wrong format
else {

    # wrong usage
    pod2usage(
        {
           -message =>
             "Wrong usage: Date range not correctly formed, should be (mm-dd-yyyy) or range (mm-dd-yyyy..mm-dd-yyyy)",
           -verbose => 1,
           -exitval => 16
        }
    );
}

print STDERR "[DEBUG] The range is correctly formulated (lower limit $min and upper limit $max)\n"
  if $debug;

# rewind the file just in case
seek FH, 0, 0;
print STDERR "[DEBUG] Rewinding the file to the beginning\n" if $debug;

# print the first line, the header
$line = <FH>;
print $line;

print STDERR "[DEBUG] Header has been inserted, now move on to sort out the file.\n" if $debug;

# define a counter of lines that pass the filter
$line_counter = 0;

print STDERR "[EXTRA DEBUG] The calculated max value is $max and min $min.\n" if $debug > 1;

# and now to process it, line by line
while ($line = <FH>) {
    my ($d, $t, $z) = split(/$sep/, $line);

    # increment the counter
    $counter{'total'}->{'value'}++;

    # get the epoch
    $e = get_epoch(\$d, \$t, \$z);

    print STDERR "\t[EXTRA DEBUG] Epoch $e (" . sprintf "%s)\n", substr $line, 0, 45 if $debug > 2;

    # check if we are about to print the line or not
    if ($e <= $max && $e >= $min) {

        # check for keywords
        if ($#keywords > 0) {
            my $skip = 1;
            my $lc   = lc($line);

            # "fix" the line (remove spaces)
            $lc =~ s/\s+//g;
            $lc =~ s/\s//g;
            $lc =~ s/\x00//g;

            foreach (@keywords) {
                next unless $skip;
                $skip = 0 if $lc =~ m/$_/;
            }

            # if the line is not matched in keywords then we skip it....
            $counter{'skip_keyword'}->{'value'}++ if $skip;
            next if $skip;
        }

        # now to check for whitelisting
        if ($#whitelist > 0) {
            my $skip = 0;
            my $lc   = lc($line);

            # "fix" the line (remove spaces)
            $lc =~ s/\s+//g;
            $lc =~ s/\s//g;
            $lc =~ s/\x00//g;

            foreach (@whitelist) {
                next if $skip;
                $skip = 1 if $lc =~ m/$_/;
            }

            # if this is a "known good" or a whitelisted value, then we skip it...
            $counter{'skip_whitelist'}->{'value'}++ if $skip;
            next if $skip;
        }

        # increment the counter
        $counter{'filter'}->{'value'}++;

        $line_counter++;    # we got a hit
        print STDERR "\tHIT\n" if $debug > 2;

        # calculate a random number
        $rand_number = int(rand(100000000));
        $part_of_line = substr $line, 45, 40;

        if (exists $p_line{$e}->{ $rand_number . $part_of_line }) {
            print STDERR "[WARNING] The same value has occured, trying to find a unique one\n"
              if $debug;

            # there is a collision in the "random" values
            # find new values until there isn't...
            while (exists $p_line{$e}->{ $rand_number . $part_of_line }) {

                # calculate a new value
                $rand_number = int(rand(100000000));
            }
        }

        # and now we are ready to assign the line to the hash
        $p_line{$e}->{ $rand_number . $part_of_line } = $line;
    }
    else {

        # not about to print, but we need to check it out a bit closer
        if ($line =~ m/SUSP ENTRY -/ && $line =~ m/FN rec AFTER/) {

            # now we have a possible timestomping activity outside the date scope
            # include it in a different hash, which we can expand if needed

            # calculate a random number
            $rand_number = int(rand(100000000));
            $part_of_line = substr $line, 45, 40;

            if (exists $stomp_line{$e}->{ $rand_number . $part_of_line }) {
                print STDERR "[WARNING] The same value has occured, trying to find a unique one\n"
                  if $debug;

                # there is a collision in the "random" values
                # find new values until there isn't...
                while (exists $stomp_line{$e}->{ $rand_number . $part_of_line }) {

                    # calculate a new value
                    $rand_number = int(rand(100000000));
                }
            }

            # and now we are ready to assign the line to the hash
            $stomp_line{$e}->{ $rand_number . $part_of_line } = $line;
        }
    }
}

print STDERR
  "[DEBUG] Done comparing lines, total number of lines that fall into the date range is: $line_counter \n"
  if $debug;

# check if there are any timestomping lines (or possible suspsects, that is)
if (scalar(keys %stomp_line) > 0) {

    # set the answer to null
    my $answer = '';

    # check if we are by default including the timestomp or excluding that information
    $answer = 'y' if $include_timestomp;
    $answer = 'n' if $exclude_timestomp;

    if ($answer eq '') {
        print STDERR "There are "
          . scalar(keys %stomp_line)
          . " that fall outside the scope of the date range, yet show sign of possible timestomping.
Would you like to include them in the output? [Y/n] ";
        my $answer = <STDIN>;

        $answer =~ s/\n//g;
        $answer =~ s/\r//g;
    }

# we need to expand the timeline with the events found outside date range that show signs of tampering
    if ($answer eq '' or lc($answer) eq 'y') {

        # expand the P_line hash with the content of stomp_line
        @p_line{ keys %stomp_line } = values %stomp_line;
    }
}

my %uniq = ();

# and now to print all the lines
foreach my $epoch (sort { $a cmp $b } keys %p_line) {

# go through each line within each Epoch time and remove duplicates before printing
# this is a very simple method to remove duplicate, however.... there is one inherent flaw in this approach
# it assumes that duplicates are true duplicates, that is all of the fields are the same.... in reality we have duplicates
# coming from different files, such as NTUSER.DAT in the user home profile corresponds to the same entry in a restore point (or points)
# so to truly remove duplicates we would have to ignore the filename and collect all filenames containing the same entry and replace the
# filename entry with the new aggregated one....

# one method is to create a new hash, containing all the lines without the filename (while storing the filename), and then removing duplicates
    %uniq = undef;
    foreach (keys %{ $p_line{$epoch} }) {
        my @f = split(/,/, $p_line{$epoch}->{$_});
        my $t = join(',', @f[ 0 .. 11 ]);

        # the key to the uniq array is the text itself (making it unique)
        if (defined($uniq{"$t"})) {

            # assign the filename
            $uniq{"$t"}->{'filename'}->{ $f[12] } = 1;
            $uniq{"$t"}->{'inode'}->{ $f[13] }    = 1;
            $counter{'duplicate'}->{'value'}++;

            printf STDERR "[L2T] Remove duplicate entry {%s} (filename: %s) old [%s]\n", $t,
              join(' ', keys %{ $uniq{"$t"}->{'filename'} }), $f[12]
              if $debug > 1;
        }
        else {

            # not defined, let's do it now
            $uniq{"$t"} = {
                'filename' => { $f[12] => 1 },
                'inode'    => { $f[13] => 1 },

                #'text' => join( ',', @f[0..11] ),
                'leftovers' => join(',', @f[ 14 .. 16 ])
                          };
        }

        # check if we are about to draw scatter plot
        if ($draw_scatter_plot) {

            # check if this is a NTFS File within the system32 directory
            if ($f[4] eq 'FILE' and $f[5] =~ m/NTFS/ and $f[10] =~ m/windows\/system32/i) {

                # check if this is the creation time (FILENAME)
                $scatter{ $f[12] }->{'FN'} = $f[0] . ' ' . $f[1] if $f[6] =~ m/FN.+B/;

                # check if this is the creation time (STDINFO)
                $scatter{ $f[12] }->{'SI'} = $f[0] . ' ' . $f[1] if $f[6] =~ m/SI.+B/;

                # and include the MFT number
                $scatter{ $f[12] }->{'inode'} = $f[13];
                $scatter{ $f[12] }->{'notes'} = $f[14];
            }
        }
    }

# now the new hash contains the line up to the filename, while storing the filename seperately, now we can sort the unique entries based on the
# text field

    # find unique entries and print all the remaining lines
    foreach $line (keys %uniq) {
        next if $line eq '';
        print $line . ','
          . join(' ', keys %{ $uniq{"$line"}->{'filename'} }) . ','
          . join(' ', keys %{ $uniq{"$line"}->{'inode'} }) . ','
          . $uniq{"$line"}->{'leftovers'};
    }

    #	foreach $line ( keys %{$p_line{$epoch}} )
    #	{
    #		print $p_line{$epoch}->{$line};
    #	}
}

# check if we are about to draw a scatter plot
if ($draw_scatter_plot) {
    open(SP, '>' . $scatter_file . '.dat');
    my %fn;
    my %si;

    foreach (keys %scatter) {

        # the structure of the dat file is:
        # MFT	FILE	CREATE_SI	CREATE_FN
        my $a = defined $scatter{$_}->{'SI'} ? $scatter{$_}->{'SI'} : 0;
        my $b = defined $scatter{$_}->{'FN'} ? $scatter{$_}->{'FN'} : 0;

        my ($a1, $a2) = split(/ /, $a);
        my ($b1, $b2) = split(/ /, $b);
        my @ad = split(/\//, $a1);
        my @bd = split(/\//, $b1);
        my @ae = split(/:/,  $a2);
        my @be = split(/:/,  $b2);

        my $d1 = $ad[2] . $ad[0] . $ad[1] . join('', @ae);
        my $d2 = $bd[2] . $bd[0] . $bd[1] . join('', @be);

        # populate the SI and FN hashes
        $si{ $scatter{$_}->{'inode'} } = $d1 unless $scatter{$_}->{'SI'} == 0;
        $fn{ $scatter{$_}->{'inode'} } = $d2 unless $scatter{$_}->{'FN'} == 0;

        print SP $scatter{$_}->{'inode'} . "\t" . $_ . "\t$d1\t$d2\n";
    }

    close(SP);

    # start by
    my @fn_outliers = find_outliers(\%fn);
    my @si_outliers = find_outliers(\%si);

    if ($#si_outliers > 0 or $#fn_outliers > 0) {
        open(OUTLIERS, '>' . $scatter_file . '_outliers.txt');

        print STDERR "Outliers were detected, "
          . sprintf("%d", $#si_outliers + $#fn_outliers + 2)
          . " in total.
Outliers or anomalies in this dataset, that compares MFT numbers of files inside the WINDOWS/System32 directory might be an indication
of a malware activity, although it could also be a sign of small normal changes made to the folder.  This technique can nonetheless be 
used for data reduction inside the SYSTEM32 directory.

The file "
          . $scatter_file
          . ".dat contains all the values used to calculate the graph, it can either be opened using Excel (tab delimited file)
to draw a scatter plot.  That is a quick way to manually find the most obvious outliers/anomalies.  However the tool l2t_process does make an 
attempt of detecting the outliers in the dataset, although it may contain many false positives, and possibly some false negatives, so it may be
wise to double check the graph visually as well.

The output of the possible outliers has been saved in the "
          . $scatter_file
          . "_outliers.txt file\n";
    }

    my %common;

    if ($#si_outliers > 0) {
        print OUTLIERS "SI outliers found [$#si_outliers in total]:\n";
        foreach my $si (@si_outliers) {
            foreach (keys %scatter) {
                print OUTLIERS "\t[$si] " . $_ . ' [' . $scatter{$_}->{'notes'} . "]\n"
                  if $scatter{$_}->{'inode'} == $si;
            }

            # check if we have a match in the fn_outliers
            foreach my $fn (@fn_outliers) {
                $common{$si} = 1 if ($fn == $si);
            }
        }
        print OUTLIERS "\n";
    }

    if ($#fn_outliers > 0) {
        print OUTLIERS "FN outliers found [$#fn_outliers in total]:\n";
        foreach my $fn (@fn_outliers) {
            foreach (keys %scatter) {
                print OUTLIERS "\t[$fn] " . $_ . ' [' . $scatter{$_}->{'notes'} . "]\n"
                  if $scatter{$_}->{'inode'} == $fn;
            }

            # check if we have a match in the si_outliers
            foreach my $si (@si_outliers) {
                $common{$fn} = 1 if ($fn == $si);
            }
        }
        print OUTLIERS "\n";
    }

    if (scalar(keys %common) > 0) {
        print OUTLIERS "\n\nThere are "
          . scalar(keys %common)
          . " common entries inside the outliers.  They are: \n";
        foreach my $key (keys %common) {
            foreach (keys %scatter) {
                print OUTLIERS "\t[$key] " . $_ . ' [' . $scatter{$_}->{'notes'} . "]\n"
                  if $scatter{$_}->{'inode'} == $key;
            }
        }
    }

    close(OUTLIERS);
}

print STDERR "[DEBUG] Everything has been completed.\n" if $debug;

# print statistics
print STDERR "\n";
foreach (keys %counter) {
    print STDERR $counter{$_}->{'text'} . ' = ' . $counter{$_}->{'value'} . "\n";
}

# print the final counter
#printf STDERR "Total number of printed events: %d\n", $counter{'total'}->{'value'} - $counter{'duplicate'}->{'value'};

printf STDERR "Run time of the tool: %d sec\n", time - $start_time;

# check if we are about to draw a scatter plot file
# The scatter plot is basically two files, one .dat file and one .cmd file that should
# gnuplot should be run against
if ($draw_scatter_plot) {

    # open the file
    open(SPF, '>' . $scatter_file . '.cmd');

    print SPF '
# gnuplot script
# created by log2timeline, or more specifically l2t_process

set terminal png
set output "' . $scatter_file . '.png"

# set the labels
set xlabel \'$MFT number\'
set ylabel \'Creation Time (YYYYMMDD)\'

# grap title
set title \'Scatter Plot, WINDOWS\system32 creation time vs. MFT numbers\'

# format of the y|x-axis
set format y "%6.0f"
#set xtics rotate -45 500

# and create the plot....
plot \'' . $scatter_file . '.dat\' using 1:($3/1000000) title \'$STDINFO\' lt 1 lw 1 pt 6, \
	\'' . $scatter_file . '.dat\' using 1:($4/1000000) title \'$FILENAME\' lt 3 lw 1 pt 4
	';

    close(SPF);

    print STDERR "Scatter plot files have been created, please run : 'gnuplot "
      . $scatter_file
      . ".cmd' to generate the graph "
      . $scatter_file
      . ".png\n";
}

exit 0;

####################################################################################################################################
#	verify
####################################################################################################################################
#
# A small sub routine that verifies if we are really dealing with CSV file.
# It simply reads the first line to see if it has the correct structure,
# and if it does, it then reads a second line to see the time zone.
sub verify {

    # check first line
    my $line = <FH>;
    my $check;

# should be
# 	date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra

    $check = 'date' . $sep . 'time' . $sep . 'timezone';

    if ($line =~ m/^$check/) {
        $line = <FH>;
        my @a = split(/$sep/, $line);

        # assign the timezone
        $zone = $a[2];

        # some dirty hack to fix some weird DateTime issuze
        $zone = 'CET'     if $zone eq 'CEST';
        $zone = 'EST5EDT' if $zone eq 'EDT';
        $zone = 'CST6CDT' if $zone eq 'CDT';

        print STDERR "Timezone not defined inside the timeline... something is wrong!\n"
          if $zone eq '';
        return 0 if $zone eq '';

        # rewind
        seek FH, 0, 0;

        return 1;
    }

    return 0;

}

sub get_epoch($$$) {
    my $date = shift;
    my $time = shift;
    my $tz   = shift;
    my $d;
    my $ee;

    # split the date (MM/DD/YYYY) into variables
    my ($month, $day, $year) = split(/\//, $$date);

    # and now to split the time (HH:MM:SS)
    my ($hour, $minute, $sec) = split(/:/, $$time);

    # use the mktime command:
    #	mktime ($sec, $min, $hour, $day, $mon, $year, $wday, $yday);
    #return mktime( $sec, $minute, $hour, $day, $month, $year - 1900, 0, 0 );

    # calculate the Epoch time
    $ee = mktime($sec, $minute, $hour, $day, $month - 1, $year - 1900, 0, 0);

    # and now to take into account the offset
    #$ee += $t_ofs;

    # and return the value
    return $ee;

    # the old method, not optimal since it is really slow
    #	eval
    #	{
    #		# construct a hash of the date
    #		$d = DateTime->new(
    #			year    =>      $year,
    #			month   =>      $month,
    #			day     =>      $day,
    #			hour    =>      $hour,
    #			minute  =>      $minute,
    #			second  =>      $sec,
    #			time_zone       => $$tz
    #		);
    #	};
    #	if( $@ )
    #	{
    #		print STDERR "[ERROR] Unable to change time (msg: $@)\n";
    #		return 0;
    #	}
    #
    #	if( $ee != $d->epoch )
    #	{
    #		print STDERR "[MISMATCH] DateTime (" . $d->epoch . ") MKTIME ($ee) [$$date - $$time]\n";
    #	}
    #
    #	# return the date in UTC
    #	return $d->epoch;

}

#	calc_max
#
# A simple subroutine that takes as an input the date
# as it was passed to the tool and calculates the
# Epoch value, that can be used later in the tool to
# evaluate dates
sub calc_max($) {
    my $max_calc = shift;
    my $d;    # the date object

    my ($a2, $b2, $c2) = split(/-/, $max_calc);

    #print STDERR "[DEBUG] Calculating the upper date: " if $debug;

    # now to create the min and max values
    if ($reverse) {

        #print STDERR "Day $c2, Month, $b2 and Year $a2\n" if $debug;

        $d = DateTime->new(
                           year      => $a2,
                           month     => $b2,
                           day       => $c2,
                           hour      => 23,
                           minute    => 59,
                           second    => 59,
                           time_zone => $zone
                          );
        my $ee = mktime(59, 59, 23, $c2, $b2 - 1, $a2 - 1900, 0, 0);

        # and now to take into account the offset
        $ee += $t_ofs;

        # check the values
        if ($debug > 1) {
            print STDERR "[DEBUG] Warning: Max value differs (DT: " . $d->epoch . " vs. MT $ee)\n"
              unless $ee == $d->epoch;
        }

        #return $d->epoch;
        return $ee;
    }
    else {

        #print STDERR "Day $b2, Month, $a2 and Year $c2\n" if $debug;

        $d = DateTime->new(
                           year      => $c2,
                           month     => $a2,
                           day       => $b2,
                           hour      => 23,
                           minute    => 59,
                           second    => 59,
                           time_zone => $zone
                          );
        my $ee = mktime(59, 59, 23, $b2, $a2 - 1, $c2 - 1900, 0, 0);

        # and now to take into account the offset
        $ee += $t_ofs;

        # check the values
        if ($debug > 1) {
            print STDERR "[DEBUG] Warning: Max value differs (DT: " . $d->epoch . " vs. MT $ee)\n"
              unless $ee == $d->epoch;
        }

        #return $d->epoch;
        return $ee;
    }

    return 0;
}

#	calc_min
#
# A simple subroutine that takes as an input the date
# as it was passed to the tool and calculates the
# Epoch value, that can be used later in the tool to
# evaluate dates
sub calc_min($) {
    my $min_calc = shift;
    my $d;    # the date object
    my $ee;

    # and now to split the values and calculate the Epoch
    my ($a1, $b1, $c1) = split(/-/, $min_calc);

    # now to create the min value
    if ($reverse) {
        eval {

            # date is formatted as yyyy/mm/dd
            $d = DateTime->new(
                               year      => $a1,
                               month     => $b1,
                               day       => $c1,
                               hour      => 0,
                               minute    => 0,
                               second    => 0,
                               time_zone => $zone
                              );
        };
        if ($@) {
            print STDERR "ERROR Calculating the date for ($min_calc). Msg: $@\n";
            return 0;
        }
        $ee = mktime(0, 0, 0, $c1, $b1 - 1, $a1 - 1900, 0, 0);

        # and now to take into account the offset
        $ee += $t_ofs;

        # check the values
        if ($debug > 1) {
            print STDERR "[DEBUG] Warning: Min value differs (DT: " . $d->epoch . " vs. MT $ee)\n"
              unless $ee == $d->epoch;
        }
        return $ee;

        #return $d->epoch;
    }
    else {
        eval {

            # date is formatted as mm/dd/yyyy
            $d = DateTime->new(
                               year      => $c1,
                               month     => $a1,
                               day       => $b1,
                               hour      => 0,
                               minute    => 0,
                               second    => 0,
                               time_zone => $zone
                              );
            $ee = mktime(0, 0, 0, $b1, $a1 - 1, $c1 - 1900, 0, 0);
        };
        if ($@) {
            print STDERR "ERROR Calculating the date for ($min_calc). Msg: $@\n";
            return 0;
        }

        # and now to take into account the offset
        $ee += $t_ofs;

# check the values
#print STDERR "[DEBUG] Warning: Max value differs (DT: " . $d->epoch . " vs. MT $ee)\n" unless $ee == $d->epoch;
        if ($debug > 1) {
            print STDERR "[DEBUG] Warning: Min value differs (DT: " . $d->epoch . " vs. MT $ee)\n"
              unless $ee == $d->epoch;
        }
        return $ee;

        #return $d->epoch;
    }

    return 0;
}

sub find_outliers($) {
    my $data = shift;
    my %outlier;
    my @keys;

    # the data variable is a hash reference build in the following way
    # key: 		MFT number
    # value:	DATE

    # "simple" approach
    # Find the UQ and LQ and calculate the ICQ
    # ICQ = UQ - LQ
    # then we have outliers if the following condition is met:
    #	x >  1.5 * ICQ + UQ
    #	x < LQ - 1.5 * ICQ

# since our line is split up in several lines really we need to start by splitting the graph into "areas"
# then calculate the UQ/LQ/ICQ for each area before we detect outliers in that dataset

  # we therefore need to define a difference value in the MFT numbers, so we can divide the data set
  # this is based upon days
    my $difference_value = 5;
    my $cur_date         = 0;
    my $thres            = 0;
    my $first            = 1;
    my $index            = 0;
    my $reset_thres      = 0;
    my @out;

# check the behaviour (want we all treated as one big slice or do we want to attempt to split the data set into pieces)
    if ($treat_scatter_as_one_slice) {

        # just treat as one big slice
        foreach my $mft (sort { $a <=> $b } keys %{$data}) {
            push(@keys, $mft) unless $data->{$mft} == 0;
        }
        @out = calc_outliers_slice($data, @keys);

        return @out;
    }

    # sort the values, based on MFT numbers, and then compare them to be able to divide
    foreach my $mft (sort { $a <=> $b } keys %{$data}) {

        # add the key to an array
        push(@keys, $mft);

        # check
        if ($first) {
            $cur_date = int($data->{$mft} / 1000000);
            $first    = 0;
            next;
        }

        # find the date portion
        my $cmp = int($data->{$mft} / 1000000);

        if (   ($data->{$mft} > ($cur_date + $difference_value))
            or ($data->{$mft} < ($cur_date - $difference_value)))
        {

            # we might have an outlier or we are in a new slice
            $thres++;    # increment the threshold
            $reset_thres = 1;

            # check if we've reached the threshold
            if ($thres > 10) {

                #print STDERR "RANGE: $index TO $#keys\n";
                # now we can slice and dice....
                @out = (@out, calc_outliers_slice($data, @keys[ $index .. $#keys - 11 ]));

           # now we are starting everything again, so we need to update variables and reset counting
                $index = $#keys - 10;
                $first = 1;
                $thres = 0;
            }
        }
        else {

            # just a normal dataset
            $thres = 0 if $reset_thres;
            $cur_date = int($data->{$mft} / 1000000);
        }

        #print STDERR "$mft [" . $data->{$mft} . " - $cmp]\n";
    }

    # check the last run
    if ($index < $#keys) {
        @out = (@out, calc_outliers_slice($data, @keys[ $index .. $#keys ]));
    }

    return @out;
}

sub calc_outliers_slice($$) {
    my $data  = shift;
    my @slice = @_;
    my @out;

    print STDERR "[OUTLIERS] Calculating slice ranging from "
      . $slice[0] . " to "
      . $slice[$#slice] . " ("
      . sprintf("%d", $#slice + 1)
      . " entries)\n"
      if $debug;

    if ($#slice == 0) {
        print STDERR "[OUTLIERS] Only one entry => it is an outlier\n" if $debug;
        return @slice;
    }

    # calculate the values needed
    my ($lq, $uq, $icq);

    # divide the number of events by four to find the quartiles
    my $div = int($#slice / 4);

    # now we need to build the value array
    my @vals;
    foreach (@slice) {
        push(@vals, $data->{$_});
    }

    # sort the values
    @vals = sort { $a <=> $b } @vals;

    print STDERR "[OUTLIERS] About to use the dividers: $div and " . $div * 3 . "\n" if $debug;
    print STDERR "[OUTLIERS] Number of entries: slice $#slice and values $#vals\n"   if $debug;

    # then find the values needed
    $uq  = $vals[ $div * 3 ];
    $lq  = $vals[$div];
    $icq = $uq - $lq;

    if ($div == 0) {
        $lq  = $vals[0];
        $uq  = $vals[$#vals];
        $icq = $uq - $lq;
        print STDERR
          "[OUTLIERS] Too few values, UQ and LQ are chosen as the first and last value in the data set\n"
          if $debug;
        print STDERR "[OUTLIERS] The UQ value of the MFT is: "
          . $slice[$#vals]
          . " - transforming to the value "
          . $uq . "\n"
          if $debug;
        print STDERR "[OUTLIERS] The LQ value of the MFT is: "
          . $slice[0]
          . " - transforming to the value "
          . $lq . "\n"
          if $debug;
    }
    else {
        print STDERR "[OUTLIERS] The UQ value of the MFT is: "
          . $slice[ $div * 3 ]
          . " - transforming to the value "
          . $uq . "\n"
          if $debug;
        print STDERR "[OUTLIERS] The LQ value of the MFT is: "
          . $slice[$div]
          . " - transforming to the value "
          . $lq . "\n"
          if $debug;
    }

# check if the $ICQ is empty (seems to be possible these days) - and if so we will assign it a number,
    $icq = 30000 if $icq == 0;

    print STDERR "[OUTLIERS] This makes the ICQ = $icq\n" if $debug;

    # now to go over the dataset to find outliers
    foreach (@slice) {

        #	x >  1.5 * ICQ + UQ
        #	x < LQ - 1.5 * ICQ
        if ($data->{$_} > int(1.5 * $icq + $uq)) {
            push(@out, $_);
        }
        elsif ($data->{$_} < int($lq - 1.5 * $icq)) {
            push(@out, $_);
        }
    }

    print STDERR "[OUTLIERS] Leaving the calculation routine, found "
      . sprintf("%d", $#out + 1)
      . " outliers in slice ("
      . $slice[0] . "-"
      . $slice[$#slice] . ") \n"
      if $debug;

    if ($#out == 5 and $debug) {
        print STDERR "[OUTLIERS] And they are:\n";
        foreach (@out) {
            print STDERR "\t$_\n";
        }
    }

    return @out;
}

__END__

=pod

=head1 NAME

B<l2t_process> - A small script to process the CSV output from B<log2timeline>, sorts and extracts sorten dates 

=head1 SYNOPSIS 

B<l2t_process> [OPTIONS] -b CSV_FILE [DATE_RANGE] 

=over 8

=item Where DATE_RANGE is MM-DD-YYYY or MM-DD-YYYY..MM-DD-YYYY

=back

=head1 OPTIONS

=over 8

=item B<-b|-body CSVFILE>

The name of the file that contains the CSV output produced by B<log2timeline>.

=item B<-t|-tab>

The default input to the tool is a file that was created using the CSV output module.  However, the TAB module can also be used, however you will need to tell the tool that the file is TAB delimited instead of comma separated, using this option.

=item B<-i|-include>

The tool detects possible timestomping activity against changes made to MFT records (millisecond is of zero value). This option makes the tool add lines that contain suspicious entries even though they fall outside the supplied date filter.

=item B<-e|-exclude>

The tool detects possible timestomping activity against changes made to MFT records (millisecond is of zero value). If this option is supplied the tool will not ask the user to add the lines that are suspicous yet are outside the supplied date range.

=item B<-v|-verbose>

Making the script produce mode debug information (be more verbose)

=item B<-y>

The default format for the date variable is mm-dd-yyyy, however this default behavior can be changed with this option so the format read is yyyy-mm-dd.

=item B<-V|-Version>

Print the tools version number and exit.

=item B<-k|-keyword FILE>

Include a keyword file that contains one keyword per line.  The tool will read the keyword file line-by-line, and then compare each line in the CSV file against each of those keywords.  The tool will only print out those lines that match the keywords.

The words inside the keyword list are case insensitive.

=item B<-w|-whitelist FILE>

Include a keyword file that contains one keyword per line. The file has the same format as the keyword file, and does the same thing, except that this file lists up keywords of words that should not be contained in the timeline. That is to say, this file defines the "known good" or whitelisted lines that should be kept out of the timeline. 

The tool starts by comparing the known keywords before processing the whitelist, meaning that keywords are first filtered out before the whitelist is processed. So the whitelist can be used in conjunction to the blacklist to narrow down the scope even more.

It can also be used to remove known "good entries" or entries that are not relevant to the current investigation out of the timeline.

=item B<-s|-scatter FILE>

This only makes sense when the timeline contains records from the MFT parser (NTFS filesystem). Then the tool will take the creation time of each file that resides in the WINDOWS/System32 directory and scatter plot it against the MFT number of that file. The tool will both plot the $FN and $SI creation time of the file.

This can be useful during malware investigations, to quickly find files that might have been added to the system32 folder. When the operating system in installed, and during patching there are usually several files written to the system32 folder at once and since MFT's are associated sequentially there should be clear association between MFT numbers and creation time. However a typical malware does not create several files in the system32 directory, a typical malware tries to hide and does so by creating as few files as possible. That makes it possible to view a scatter plot, showing the relationship between creation time and MFT numbers to quickly spot those outliers or anomalies. This technique can therefore be used for data reduction.  

This option creates a simple gnuplot data file and a gnuplot script that can be used to create a simple scatter plot to see those outliers. It will also make an attempt at identifying those outliers with a simple algorithm. By default the tool treats the entire dataset as a single slice and tries to find the obvious outliers, however that behaviour can be changed using the -m or --multi option to tell the tool to try to split the dataset into slices.

The FILE portion should be the name of the output file the tool writes to, it should only contain ASCII letters: a-z, A-Z, underscore (_) and numbers 0-9, no dot.  The files created will be:
FILE.dat and FILE.cmd

Then the tool gnuplot has to be run, like:

gnuplot FILE.cmd

Which will produce a file called FILE.png, containing the scatter plot.

If the tool detects any outliers in the dataset then the file FILE_outliers.txt will be created. That file will contain a list of all those files that the tool detected as outliers.

=item B<-m|--multi>

This option is only available when used with the -s FILE, to create scatter plot of the creation time vs. $MFT entry numbers. By default the tool treats the entire dataset as a single slice and tries to detect outliers in it. Since the relationship between $MFT entry numbers and creation time isn't a simple line, in reality it consists of several straight lines, there will be many false negatives when treating the dataset as a single slice. Therefore the option of trying to split the dataset into multiple smaller slices, and calculating the outliers for each one of those has been provided. 

This is a simple approach to this problem, and by no means solves the issue at hand. This method does produce lots of false positives (and it could also miss some, or produce false negatives). However it will catch many of the items that get missed by the first attempt. 

Perhaps the best approach is to start with the default behaviour of the tool, examine the graph manually. And if there are some outliers in the dataset that are perhaps aligned with another line, yet are obvious outliers, then to re-run the tool using this option to try to see if it gets detected.

=item B<-h|-help>

Print this help message

=item B<[DATE_RANGE]>

The date range is formulated as one of the following:

=over 16

=item MM-DD-YYYY

All dates from the date supplied date and forward from them.  That is to say, the date defines the starting date and all dates after that date will be part of the selection.

=item MM-DD-YYYY..MM-DD-YYYY

This is a range, so all events that fall within the boundaries set by these two dates will be part of the selection.

=back

=back

=head1  DESCRIPTION

B<l2t_process> takes as an input the CSV output produced from the CSV output module of B<log2timeline> and sorts the file.  It also has the capability to only let the file contain entries from a certain date range, or a similar behavior of the tool mactime from the SleuthKit (which works on mactime body files).

The tool also removes any duplicate entries that might appear in the timeline. This can occur when recursive scans are made, since the same timestamp can be present in more than one file, such as registry entries both in NTUSER.DAT and inside various restore points.  The tool will remove the duplicate entries and change the filename so it includes all the files that the timestamp is found in.

There is also "timestomp" detection, in the sense that if you used the MFT module of log2timeline to parse the NTFS $MFT file, and there are entries that have zero nanoseconds (second precision), which might be an indication of timestomping (since those tools only work on 32-bits of the timestamp, that is up to the second).  So if you run the tool with limited date range, and there are entries that fall outside the date entry that have zero nanoseonds (second precision), the tool will ask if you would like to include them in the timeline.

=head1  EXAMPLES

Process the file combined.txt and only include entries that occured from January the 1st, 2004,  until March the 31st the same year.

l2t_process -b combined.txt -y 2004-01-01..2004-03-31  >  examine.txt

Go over the file combined.txt and only include lines that fit the keyword list provided in the file dirty.txt

l2t_process -k dirty.txt -b combined.txt > dirty.txt

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

The tool is released under GPL so anyone can contribute to the tool.  

=head1 COPYRIGHT AND LICENSE

Copyright 2009-2011 by Kristinn Gudjonsson (kristinn ( a t ) log2timeline ( d o t ) net ) 

B<log2timeline> is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

B<log2timeline> is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with B<log2timeline>.  If not, see <http://www.gnu.org/licenses/>.

=cut
