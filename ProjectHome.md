This project has been deprecated in favor of the new backend engine called plaso, see more information [here](http://plaso.kiddaland.net) and [here](https://code.google.com/p/plaso).

This small little project site is dedicated to the tool log2timeline, a framework for automatic creation of a super timeline. The main purpose is to provide a single tool to parse various log files and artifacts found on suspect systems (and supporting systems, such as network equipment) and produce a timeline that can be analysed by forensic investigators/analysts.

This tool hosts the now old Log2Timeline Perl based backend engine for log2timeline, an engine that has been deprecated. The new shiny thing that has replaced it is: [https://code.google.com/p/plaso](https://code.google.com/p/plaso). Plaso is the Python based backend engine that is currently used for log2timeline, as of version 1.x (that is the Perl version is version 0.x of log2timeline and plaso is version 1.0+).

The new official site for the tool is: [here](http://plaso.kiddaland.net)

N.b. there are still few parsers that have not yet been ported over to the next great thing (plaso), so there may sometimes still be a reason to use the old Perl tool. Some of these plugins may never be ported over, since they were created as a one-off to a particular investigation. Others are being ported over as time allows. However there are also quite a few parsers only available in plaso and all new parsers are solely going to be implemented in plaso.

And now the old text that still remains somewhat accurate:

This old backend engine is written in Perl for Linux but has been tested using Mac OS X (10.5.7+ until 10.8). It mostly works with Windows (with ActiveState Perl installed), that is it should work just as it does in Linux, it just hasn't been tested as much (as in very little).

I started this project after a discussion with [Rob Lee](http://www.sans.org/instructors/rob-lee) about possible topics I could choose for my SANS Gold paper. Rob had this great idea of wanting a tool that could take timeline analysis to a new level. That is to create a single tool that could parse various artifacts found on a suspect drive and include them in the timeline, a some sort of super timelining, more background can be found [here](http://computer-forensics.sans.org/blog/2011/12/06/how-to-make-a-difference-in-the-digital-forensics-and-incident-response-community). The Gold paper, titled "Mastering the Super Timeline With log2timeline" can be downloaded from [here](http://www.sans.org/reading_room/whitepapers/logging/mastering-super-timeline-log2timeline_33438).

And if the gold paper isn't enough (or too old since it discusses version 0.50 of the tool), or too much, it is always possible to refer to the man page for a description of the tool or to the wiki on this site, blog entries that can be found on the wiki, BlogEntries, for examples of usage and a better description. And as always, better documentation is on the way... (one source being this wiki).

If you like the tool, please consider donations to help keep the project alive.