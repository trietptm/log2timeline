**warning: this document has not yet been completed... it's a work in progress... it has nonetheless been released now, just as a reference today.**

# Introduction #

This style guide is not intended to make any claims of how to develop in Perl, nor does it necessarily make any claims that one style or what is written here is or should be considered as a best practice in Perl coding or in general coding.

This style guide is intended to make this particular code more readable and thus more maintainable by me and those that might want to maintain it.

The intention is to make the tool written in the same way. As many know writing code in Perl can be done using various methods, the motto of 'there is more than one way to do things' can make the code more difficult to maintain/read.

This page should describe how one should write code that is submitted to the project, mainly to make it all written in the same style, so that it will be easier for everyone to read and make modifications to the code.

One important disclaimer! This style guide is written after substantial code has been committed to the project, thus not all of the current code might be written accordingly. However, no new code will be allowed to be submitted to the project unless it adheres to the style, and all updates to the code wil include inspection of the style.

If not otherwise overruled by this guide, please follow [Perl Style Guide](http://perldoc.perl.org/perlstyle.html). And especially the first part of it where the main points are laid out, they all apply.



# General Guidelines. #

Few general guidelines that should apply over all sections of the code writing:

  * New modules and new features should be first commited into the "experimental" branch before being merged into the master one.
  * Use of '_use_ _strict_' is mandatory for all scripts commited to the project.
  * Variable re-use. It is a common trap that people declare frequently used variables once and then re-use them throughout the code. This can lead to both confusion and difficult to debug errors and should be discouraged at all times. It also makes maintenance more difficult.
  * Correct spelling. This should be enforced over all the spectrum, whether that applies to variable names, comments or strings printed out in the tool.

Perl tidy can be used to assist with some of the style problems. It will enforce a lot of the rules that are listed here (although not all of them).  A configuration file for perltidy has been created that enforces some of the rules listed here. It can be found inside the dev/ directory in the source repository.

To use perltidy (after installing it):

```
perltidy -b -pro=PATHTOSOURCE/dev/perltidy.conf MODULE.pm
```
eg.
```
perltidy -b -pro=../../../dev/perltidy.conf MODULE.pm
```

# Code Review. #

All code that is submitted by external developer, where external means everyone else than the original developer (Kristinn), needs to go through a code review. The code review will include a review of both the style, speed, accuracy and other things that might come up. The code review process has not been perfected and will not catch every bug in the potential code, but it will however hopefully mean that less bad code be submitted to the project. If the project gains enough attention so that some other maintainer will take a part of being a lead developer, then all commits to the project should go through the code review.

# Details #

The list that follows is in no particular order, it will list up all the rules that I can think of that should apply to the code development.

## Templates. ##

Templates for developing modules can be found within the dev/ directory in the source code. The currently available templates are:
  * **template\_for\_input\_module\_logfile.pm** - This provides a simple skeleton to develop a new input module.
  * **template\_for\_output\_module.pm** - This provides a simple skeleton to develop an output module.
  * **example\_simple\_frontend.pl** - This provides a simple example of a new frontend that uses the Log2Timeline API.

Use templates when developing new modules. Either by copying already existing modules or by copying the templates themselves. These will assist with setting up all necessary variables, and contain headers and other copyright disclaimers/banners/headers.

## Comments. ##

Comments are made in the plain old documentation format, or POD http://perldoc.perl.org/perlpod.html.

Examples:
```
=head1 NAME

B<log2timeline> - a log file parser that produces a body file used to create timelines (for forensic investigations).

=head1 SYNOPSIS 

B<log2timeline> [OPTIONS] [-f FORMAT] [-z TIMEZONE] [-o OUTPUT MODULE] [-w BODYFILE] LOG_FILE/LOG_DIR [--] [FORMAT FILE OPTIONS]

=head1 OPTIONS

=over 8

=item B<-s|-skew TIME>

Description of field

=back
```

The following are general rules regarding the syntax of POD in terms of log2timeline usage:
  * **=head1** - Used with POD fixed named structures, such as NAME, DESCRIPTION, SYNTAX.
  * **=head2** - Subheader, such as name of method within METHODS head1. Method name should be surrounded with `C<NAME>`.
  * **=head3** - Within the context of methods, this is one of three things: Args:, Returns:, Raises:
  * **=head4** - Within Args:, ..., it describes each value/variable that is used.

An example of this should be:
```
=head2 C<calculate_timezone>

This is a method that accepts both a timezone and an offset and calculates the difference between the current date and one if it used that offset and timezone.

=head3 Args:

=head4 Timezone - A string that represents the timezone of the file in question.

=head4 Offset - An integer that indicates the offset of time, in seconds. Might be both positive and negative integer.

=head3 Returns:

=head4 The number of seconds between current timezone and the one offered, with the offset in mind.
```

If the code is properly commented it can be accessed easily using the man pages of **NIX, such as
`man Log2t::input::iehistory`**

The general rule of thumb is to put all comments about a subroutine inside the pod description and keep internal comments (lines starting with #) at a minimum. However it might still sometimes be necessary to include some inline comments, for instance to further explain some logic (if during a code review you are asked to explain a certain logic, it should be further commented in the code).

## Headers ##
All files should start with this structure of comments (remember dates of module creation are stored in DD/MM/YYYY).

```
#################################################################################################
#               NAME OF MODULE       
################################################################################################# 
# Author: name of developer
# Version : 0.1
# Date : 15/01/12
#
# Copyright 2009-2012 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

nameofmodule - A one line description of the module, what it does, etc.

=head1 DESCRIPTION

Small description of the module, what it's purpose is, how it does stuff, etc.... links to relevant 
information, such as links that describe the structure, or it's evidentiary values, blog posts
discussing how to interpret the results, etc....
 
=head1 METHODS

=over 4

=cut

```

## Indentation. ##

Indentation should be 4 spaces, and tab should be avoided (do not use tab).

If you are developing in vim you can simply update your ~/.vimrc to the following:

```
" set both tabstop and shiftwidth to 2 spaces
set sw=2
set ts=2
```

Although Perl does not enforce indentation it should nonetheless be used to make the code more readable.
Code should be indented in all loops and conditions, like:
```
if ( $number == 200 ) {
    # code inside condition is indentent
    # if this goes over multiple lines, each one is indented
    if ( $my_test ) {
        # another condition, and another indentation
    } 
    # we should end the condition with the same indentation as it started
}
```

## Loops/conditions. ##

If loops should contain the curly braces on a separate lines, both the opening and closing brace. The content within it should be intended by one tab to make it easier to read.

They should also contain parenthesis around the condition of the loop.

Examples:
```
if ( $this_variable == 1234 ) {
    # now do some stuff
}
else {
    # do something else
}
```

## Naming. ##

All variables should be given a meaningful name that corresponds to its use in the code. For instance if the purpose of the variable is to store a value that corresponds to number of lines already parsed, it could be named something like $counter\_line or $line\_counter. The name should give away it's purpose and be easily readable.

The name of a variable should also indicate whether or not it holds a single or multiple entries, such as @lines for an array of lines and $line for a variable that holds a single string.

The following naming scheme applies to modules and variable names:
| **Type** | **Example** | Description |
|:---------|:------------|:------------|
| Variable | $this\_is\_a\_value | All small caps, and uses _to distinguish between words._|
| Method name | sub do\_some\_cool\_stuff($$) | All small caps, use _to distinguish between words, and indicate the number of parameters sent to the method using the $ sign_|
| Constant | ALL\_CAPS   | Constants have all caps, and are defined using the "`use constant ALL_CAPS =>  'VALUE';`"|

## Methods ##
Each method should start with a [comment](StyleGuide#Comments..md) that describes the method.
The description should describe it's purpose and it's algorithm/how it works.

It should also contain description of all parameters and their meaning along with any potential exceptions that the method might raise and return values.

An example:
```
=head2 add_two_to_number

A simple method that adds two to each number provided.

=head3 Args:

=head4 Number: An integer that needs to be incremented by the number 2.

=head3 Returns:

=head4 The integer that was provided to the method incremented by 2.

=cut
sub add_two_to_number($) {
  my $number = shift;
  return $number + 2;
}
```

## More to follow. ##

**more to come... being worked on currently**

Again, although there is nothing else at this exact moment here, you should refer to [Perl Style Guide](http://perldoc.perl.org/perlstyle.html) for guidelines on stuff that is not listed here.

And use perltidy for the easy fix for your style (configuration file found inside the 'dev/' directory).