----------------------------------------------------------------
		README
----------------------------------------------------------------
This is the readme file of the program log2timeline

1. WHAT IS THIS?
2. DISCLAIMER
3. WHY 
4. EXAMPLES OF USAGE
5. INSTALLATION
6. WHAT TO EXPECT 
7. VERSION NUMBERING 
8. CREDIT

first small disclaimer... I do not routinely update this document, so 
some portions of it may be out-of-date....

1. WHAT IS THIS?

log2timeline is a framework built to automatically create a super
timeline using information found within various log files and other
files that contain timestamps.  The tool can be used to augment
traditional timeline analysis where the focus has generally been on 
solely the timestamps found within the filesystem itself. 
The tool is also capable of outputting into various formats that 
can be used to either import into analysis tools or to read directly
using whatevery suits you (spreadsheet/vim/less/...) 

So in short, the tool is intended to be used to create a timeline
using information found within artifacts on systems or in log files, 
perhaps found on different systems, to collaborate or further strengthen 
an investigation.  This timeline augments the traditional one, and is 
sometimes referred to as a super timeline.  

This tool started out as a SANS Gold paper project - and the gold paper
titled "Mastering the Super Timeline - log2timeline Style" can be read
from the SANS web site. (links also available from the log2timeline web
site).

As the description implies this is a forensic tool, but if someone else
finds other use for it, then feel free to use it ;) (and please send
feedback, I love to hear other ideas on how to use the tool).

There are three front-ends of the log2timeline tool provided.  One being
log2timeline, the CLI version of the tool, another glog2timeline, 
which is a GUI version (quite a shitty one in my opinion - discontinued now) 
for those that prefer a GUI.  The CLI version should work on other OS, such 
as Mac OS X and Windows but the GUI version depends on GTK2, so it will most 
likely only run on *NIX and Mac OS X with X11 installed (the only tested 
platforms).  The third front-end, which has been integrated into log2timeline, is 
timescanner, a recursive parser that sifts through a directory (such as a 
mount point of an image) and parses every file the tool is capable of.  
This is the automatic method of aquiring a super timeline of an image.
(note timescanner is really not necessary any more, log2timeline, the
main front-end has all the capabilities of timescanner).

1.1 Continued Development

Please consider donating to the tool to make sure it will continued to
be supported and updated in the future.  The tool is developed in my 
own free time, which is often quite limited.  Any donations will keep
me on track, and benefit the project, and hopefully by that the community
in whole.

See the donations image in the web site for information on how to 
donate to the tool.

1.2 Input modules currently supported

One disclaimer about the input modules is that they normalize all
timestamps to UTC/GMT. Many of the artifacts already store their 
timestamps using UTC timestamps yet there are those that store 
their timestamps using the local time zone settings of the machine.
Therefore it is very important to indicate which time zone is 
set up on the suspect machine.  This information is used to 
normalize all the timestamps to UTC/GMT, making it necessary to 
modify all timestamps again to properly represent them in the 
local timezone (when changed from Epoch) - that is when using output
modules such as mactime, some output modules will change the time 
back into the supplied time zone, which will be clearly marked as
such.

This tool is just as good as the number of provided formats that
this tool can parse.  Each file format has it's own input module 
that is stored in the folder Log2t/input.

Please use log2timeline -f list to see the current list of all
available formats (in case this file is not completely up-to-date)

1,3 Output modules currently supported

The tool was originally build to support mactime output. That is to output to 
a body file that can be imported into the mactime tool from TSK.  Later the tool
was split into modules, providing a output modules that provided a mean to output 
the timeline data into other formats.

Please use log2timeline -o list to get a list of supported output modules.

2. DISCLAIMER

This is still a BETA version of this tool despite all the testing that has been made. 
What still is missing before calling this another name than beta is more testing and 
verification of the result of the tool. Doing proper verification takes time and patience
and needs to be done on several different types of machines with different log files that 
have been manually validated.  Until that verification phase is done and proper testing 
has been performed I consider this tool to be a beta.

Despite being a beta release it can still be used in real cases as a mean to get a 
better overview of the suspect drive and quite possibly solve the case (well almost), but
you should not put all your faith into the results, please verify the results before taking
the output of this tool to court (and if you do verify the results and especially if you
go to court using the output of this tool as a part of the report or part of the investigation
I would love to hear from you).  

There have been (at least historically) errors/bugs in the tool where the date object had 
not been properly read in due to the fact that most of the test log files are already stored in 
GMT/UTC or simply wrong parsing of date objects, or out-of-specs formatted dates inside files.
Hopefully all those errors have been squashed, however please verify ... always verify
your results... (and provide feedback)... This is not something that is solely log2timeline
problem, this same situation should be on all other tools as well... never trust a tools
output unless you've verified it's results.

The tests that have been run show excellent results and some of it has already been
verified to be accurate.  So in theory it should show accurate and verifiable results
but I don't want to make any statements that I cannot back up so please bear that in mind.
Verify the results (and if you can, please send me back some feedback - the feedback thing
is a reoccuring theme here, if you hadn't noticed).

That being said, the tool operates correctly on those tests that have been performed, 
and until proven otherwise should work properly on all others, but please test it 
yourself before depending upon it (remember the feedback discussion we had?).  

Future versions will be tested further and hopefully the day will come when I will 
be satisfied with their result.  And of course if you encounter any errors, bugs or 
otherwise not a correct representation of your data, please contact me so that I 
can fix the code. That way I can improve the tool for others to benefit from, all bug 
reports will be taken seriously and fixed as quickly as possible so that the tool
will provide the most accurate results.

3. WHY

Timeline analysis can be extremely useful in an investigation, whether that be
a malware analysis or a HR case (or any other for that matter).  Traditional 
file system timeline can be very helpful yet it is not enough to get the big picture, 
or a complete and accurate picture of the events that happened.  Therefore it is necessary 
to examine further artifacts found on suspect systems or log files found on other devices, 
such as web servers, proxy servers, firewalls or other network equipment to get a more 
complete picture.  

This tool has been created to use those artifacts and log files in a timeline 
analysis to assist the investigator so that he/she can more easily see the "big 
picture", to more accurately build a correct timeline showing what really 
happened and when (and in which order).  Therefore for this tool to be really
useful it needs to have support for as many log files as artifacts as possible.

Please refer to the gold paper "Mastering the Super Timeline - log2timeline Style"
for further information and more detailed description of the tool and analysis
techniques.

4. EXAMPLES OF USAGE

Examples of the usage of the tool are provided in various blog articles that I 
have released or will release in the future.  The web site log2timeline.net should
keep an accurate up-to-date list of those blog posts.  

When this blog part of the README file was last updated these were the blog posts
that were available about the usage of the tool:

(exceptionally old list, and I don't want to maintain it in two places, so please
refer to the log2timeline web site for a more accurate, up-to-date list of those 
blog entries that I feel are relevant to the tools usage):

http://blog.kiddaland.net/2009/08/log2timeline-artifact-timeline-analysis-part-i/
https://blogs.sans.org/computer-forensics/2009/08/13/artifact-timeline-creation-and-analysis-tool-release-log2timeline/
https://blogs.sans.org/computer-forensics/2009/08/14/artifact-timeline-creation-and-analysis-part-2/

5. INSTALLATION

Please refer to the INSTALL document (docs/INSTALL).  In short you can
issue the following commands to built from the source files:

perl Makefile.PL
make
make install (as root user)

During the "perl Makefile.PL" all dependencies are tested, so all missing dependendcies should
produce a warning. And the INSTALL document describes some of the methods you can go through 
to get those dependencies fixed.

And if your platform offers a repository to install the tool, then that is a preferred method of 
installation.  Not only does it save you the trouble of fetching all those dependencies (which can 
sometimes be difficult or at least annoying) it also makes sure you have the latest version of 
the tool installed at all times (since it upgrades alongside the operating system).

There are currently repositories available for Ubuntu/Debian, Fedora/CentOS/RedHat and BSD/Mac OS X (ports)
that make the installation quite simple.

6. WHAT TO EXPECT

Well as this tool has been maturing more and more input modules are being added to it, 
making it already quite useful.  The main problem now begins to be the amount of 
entries it creates, so the focus of the development will shift a bit from solely 
adding new input modules to the tool towards a better tool itself, and a better support
for platforms.  So the focus will now be towards improving the framework itself, making
it easier for others to contribute to the tool, adding documentation, and starting to 
make headways into making the tool use C-libraries, such as the TSK, so that images
can be directly read instead of requiring users to mount the image prior to running
the tool.

Please refer to the document ROADMAP to see more detailed information about
where the tool is heading and what is planned in the coming releases. Usually the information
found in this part of the README file are quite obsolute, so to get a better understanding of where
the tool is heading, again take a look at the ROADMAP file.

And of course if anyone has ideas about further improvements or other log files
to be added, please either add one yourself (and send it to me to include it in 
the tool) or write to me and ask me to add it (my email is kristinn ( a t ) 
log2timeline ( d o t ) net.  

And of course if you have any comments, whether that be hate or love mail, or even in the unlikely 
event that you want to ask me some question(s), please send them as well.

For those interested in developing an input module , a file called template_for_input_module_logfile.pm
is included in the dev folder, a file that contains the skeleton of a new module that follows
the structure that needs to be implemented.  It can simply be copied and then filled in the blanks
to complete it (and then copied to the lib/Log2t/input folder). The same goes with the output 
modules, they are stored in the dev folder folder and there is a template_for_output_module.pm file that 
comes with it as well.  If you do by any change create a new input or output module, it would be 
greatly appreciated (and in fact almost required) to let me know of it, and send me the 
file (if possible) for inclusion with the tool. There are also information to be found inside
the gold paper that got release that describes the tool, and there will be a more complete API/
development reference manual released soon.

7. VERSION NUMBERING

log2timeline uses the following format for versioning:
	X.YZ
 Where each letter is substituded by a single digit.  The meaning of the digits are:
	X - major release, major changes to the program (so much major that it is still
		in version 0, and will be for I guess quite some time...
	Y - New features added to the tool, modifications other than bug fixes to the
		main script or otherwise changing the behaviour of the tool 
		This usually indicates some changes made to the tool/front-ends themselves
		or structural change of the modules, with changes made to all of them to 
		keep them working.  
	Z - New input or output modules added to the tool or small changes made to the
		front-ends. This also includes minor bug fixes.

Please refer to the CHANGELOG file to see a list of all changes made to the tool for
each release.

8. CREDIT

First of all this tool would most likely not have been created if I hadn't been 
contacted by Rob Lee, asking me if I could create a single tool to read different
log files for timeline analysis.  Before that time I had been mostly creating 
independent scripts to read each log file that I came across in my investigations.
These scripts were mostly just copy paste of one original that I wrote, so putting
them together in a single tool seemed like an excellent idea.

And of course I would like to thank all those who wrote a code under GPL that I could
include in this tool, such as the registry work that Harlan Carvey has done (included
in the RegRipper tool) that have been used.  A very special thanks go to Julien Touche,
Willi Ballenthin, Tom Webb, Hal Pomeranz and Ben Schmitt who have donated code to the project, 
Julien wrote the volatility input module, Willi the Apache2 access and error input 
modules and Ben wrote a threaded version of timescanner. Tom has also written an
Apache module that got merged into the apache2_access module written by Willi.  Julien
also created a BSD port for the tool, and merged into the standard repository.  This 
makes the installation of the tool to be exceptionally simple for all BSD systems, 
including Mac OS X (using macports). And Hal wrote an input module for the Safari plist.

And I would also liked to thank those who tested the tool and gave me feedback, such 
as Stefan Kelm and Andrew Hoog that have given me very valuable feedback as well as to 
test almost every version of the tool. Rob Lee has also tested the tool and given me 
very valuable feedback as well as Paul Bobby, Thomas Millar, Andrew Hay and others.
There have been so many people lately that have been contributing bug reports, and 
helping me to test the tool so I would like to give them all a big thank you for their
assistance into making this tool better than it was before their feedbacks.

I would like to give additional shout out to Andrew Hoog that has been extremly helpful
during the development of the tool with great feedback, discussions and wish lists.  He
also provided me with a place to store those ideas and work with them, further assisting
me in writing the tool.

I got permission from H. Carvey to include some of his work that he has done for his own
timeline toolkit into log2timeline.  So some of the input modules are taken mostly from 
his code, just adjusted so that they fit into log2timeline input module format.

I've also included the Parse::Evtx library from Andreas Schuster with his permission
to provide support for the new Windows Event Log format, EVTX.

And I would also like to thank Frank Birkmair for giving me the instructions on how
to install log2timeline in FreeBSD and OpenBSD. And Chris Pogue for giving me the
instructions on how to install the tool on the Windows platform.

