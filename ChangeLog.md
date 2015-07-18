# Changelog #
## Version 0.65 (25/09/2012) ##
  * **UTMP input** New input module parsing utmp/wtmp files in Linux, written by Francesco Picasso.
  * **SELINUX input** New input module parsing SELinux audit files in Linux, written by Francesco Picasso.
  * **l2t\_process** Renamed to l2t\_process\_old, being replaced by l2t\_process.py from l2t\*tools.
  * **EVTX Library** Fixed a small bug in the code, causing some EVTX file parsing to fail.
  * **Altiris input** Fixed a small bug when the date is malformed.
  * **Log2Timeline library** Fixed few bugs:
    * Small error in the format sort, caused oxml to sometimes be skipped in processing.
  * **GENERIC\_LINUX input** Added a small extra eval sentence.
  * **LS\_QUARANTINE** Fixed a minor bug in the get\_time routine, if a database occurs it is caught by an eval sentence.
  * **TEST** Added few more tests.
  * **MOST INPUT MODULES** Changed the line:
> > `my $line = <$fh> or return undef;`
> > in most input modules.
  * **WIN library** Added few more transformations of Windows stored time zones into a "olson" ones understood by DateTime.
  * **CHROME input** Fixed a small unicode bug in the "File Downloaded" section.
  * **CHROME/FIREFOX3/SKYPE\_SQL/LS\_QUARANTINE input** All SQLite modules changed:
    * Now the database is copied to a tmp location before parsing, since trying to parse them from a read-only medium can cause problems.
  * **faersluskra2timalina** Added a new frontend to the tool, exact copy of log2timeline, except all parameters in Icelandic... kinda Aprils fool joke, except not in April.. so enjoy (bonus points for those that manage to figure out how to use it WITHOUT using Google translate).
  * **timescanner tool** Removed this frontend from the Makefile since it serves no purpose (as in no longer part of the automatic installation).

## Version 0.64 (11/06/2012) ##
  * **TESTSUITE** Added the first version of a test suite to the tool.
    * All tests are located inside the t/ directory.
    * Tests should be constructed for ALL possible uses of the tool, not limited to:
      * Raw parsing of logs using input modules.
      * Correct output for output modules.
      * Correct output from each function inside modules/libraries.
    * The first TEST suite is raw and not nearly complete, needs loads of stuff to be 'proper' but it is a start.
  * **LS\_QUARANTINE input** A new input module that parses the LSQuarantineEvents SQLite db in Mac OS X.
  * **Log2Timeline library** Added the possibility to use a dot (.) in the exclusion list.
    * Changed the exclusion list so it can be easily changed
    * Added a call to `->end` on each input module if verification failed.
    * Minor bug fixes in the main engine.
    * Changed wording when an output module is loaded (from "Loading output file" to "Loading output module").
    * Added support to detect shortcuts in Windows systems.
    * Added the "path\_orig" to all input modules (making it possible to "fix" paths).
  * **CHROME input** Slight changes to the output based on the value of the typed\_count variable, also updated the path to the code that describes the transition types.
  * **SKYPE input** Fixed the verification routine a bit, cleaned it up slightly and fixed a small bug that caused the tool not to include SKYPE data when recursive mode was set on.
    * Also fixed UTF-8 support, should properly display UTF-8 by now.
  * **PREFETCH input** Small changes to the verification module.
  * **WinReg** Fixed a small bug in the code that caused the deleted entries lookup sometimes to loop forever.
  * **SQLITE output** Changed the way the SQLite code is written considerably, pre\*compiling statements to prevent them being compiled for each insert, using transactions instead of writing them constantly to the DB, and other minor tweaks to make the DB output faster than before (since it was increadibly slow before).
  * **CHROME input** Small bug to fix UTF-8 support.
  * **FIREFOX3 input** Small bug to fix UTF-8 support.
  * **PREFETCH input** Fixed a bug, added a seekdir so that prefetch information is contained within the timeline if recursive is turned on.
  * **RECYCLER input** Fixed a bug, added a seekdir so that recycler information is contained within the timeline if recursive is turned on.
  * **LIST files** Added few items into the Windows list files, as well as to create a Mac OS X one.
  * **MFT input** Fixed a bug with Unicode support.
  * **RECYCLER input** Fixed a small bug ([issue 5](https://code.google.com/p/log2timeline/issues/detail?id=5)) with the path not showing the correct path as indicated by --m TEXT
  * **SOL input** Fixed a small bug ([issue 5](https://code.google.com/p/log2timeline/issues/detail?id=5)) with the path not showing the correct path as indicated by -m TEXT
  * **EVTX input** Changed the dependencies to Parse::Evtx2 instead of Parse::Evtx (same library, changed the namespace).
    * Issue when Parse::Evtx was installed on SIFT, causing the tool to first load the library from Schuster, and not the slightly changed one distributed by the tool, causing the module to not work.

## Version 0.63\*1 (bug fixes) (09/04/2012) ##
  * Removed small additional debugging text from the iehistory module (shouldn't be printed unless we have debug turned on).
  * Fixed a small bug in the _open\_file function._

## Version 0.63 (09/04/2012) ##
  * ALL modules/files were run through perltidy using the configuration file of dev/perltidy.conf.
  * Also several modules have had their documentation updated and code reformed to reflect recent release of a style guide for the project. perltidy is not enough to enforce that, but at least a start. Rewriting the documentation (pod) is also a vital portion of making the modules easier to use/understand/develop.
  * All libraries within the tool and the main API have been rewritten with this in mind, making 'man' documentation considerably more useful than it was.
  * **SERIALIZE output** JSON::XS used to serialize the timestamp output, a very simple output module that simply stores
    * This makes it possible to output using this method and then sorting is simpler since it does not require the module to read in the csv and change it into something like a hash, since it is already stored as such.
    * This migh become the default output of the tool, and then run l2t\_process on that output, turning that into CSV instead of using CSV as default and trying to filter that output.
    * This also makes it easier to filter, based on certain attributes, instead of at the line level.
  * **WIN7 list** Fixed a small bug in Win7 list file (and win7\_noreg). The evt module was loaded up and not the evtx one.
  * **FIREFOX3 input** Added a check to see if the SQlite database contains a -wal or -shm (in addition to -journal)  And if it does, then do the same procedure as if it was a -journal (read-only database that gets copied to a temp location). This was pointed to me by Svante
  * **PREFETCH input** Changed the default output so that loaded DLLs are not included by default, unless the -d|--detail option/parameter is used.
  * **MFT input** Inside the verification routine a check is made to see if the magic value is FILE0, it should only be FILE.  Fixed that, making the mft module capable of parsing those $MFT files that do not the standard offset to the fixup array.
  * **SAM input** Changed the handling of SAM database data, it did not properly parse the SAM database file in certain cases due to the keys being prefilled with the CMI-CREATE....
  * **NTUSER input** Changed a value check in UserAssist key parsing causing UserAssist keys not properly being parsed.
  * **WIN\_LINK input** The values for mtime and atime got swapped (the correct order is CAM not CMA like it was)
  * **SETUPAPI input** Added a 'detailed\_time' check, to reduce the text inside the alert by default, unless detail option used.
  * **log2timeline** Updated the man page to reflect updates to the 'detailed\_time' changes to setupapi input module.
  * **WIN library** Added a mapping to map up all Windows use of timezones to the one used in the DateTime library.
  * **win\_sysinfo PreProc** Updated the pre\*processing library so that it checks if a known transform of a Windows named timezone information is available and if it is it will compare it to the chosen timezone (and change it if they differ).
  * **LOG2TIMELINE** Small bug in the log2timeline library, causing input modules list that has more than one minus (-) sign in it not properly verified.
  * **IEHISTORY input** Switched time1 and time2, and started to update the module so it adheres to the newly released, not yet complete, style guide.
  * **EVTX input** Updated the EVTX library to the latest release, version 1.1.1 (written by Andreas Schuster)
    * Also changed the 50 attempts to 15 (in case of an error in reading an entry), also only output error message if debug is turned on.

## Version 0.62 (23/11/2011) ##
  * **FF\_CACHE input** New input module, designed to parse the cache files of Firefox. Contributed by John Ritchie
  * **OPENVPN input** New input module, desigend to parse the OpenVPN log files.
  * **L2T\_PROCESS** Added a few more allowed characters in the keyword list
  * **proftpd\_xferlog input** Willi Ballenthin added a new module to parse the ProFTPD XFerlog file
  * **Log2Timeline library** Fixed a bug, when the 'all' moduiles option is used (or -f is omitted) no modules get loaded
    * Added a small change to try to parse the MFT directly even though the $MFT might not be directly visible
    * Fixed a small bug whereas the tool would crash if the local timezone was used.
    * Fixed a small bug whereas the tool is not able to find the default directory (does not exist) or if the file in question does not really exist that the tool is pointing to... that made the tool return a double error instead of  just dying on the first one.
    * The tool will now accept a separate output timezone so the tool can output in a different timezone than the hosts one.
  * **log2timeline** Added the -Z ZONE parameter so the tool can output in a different timezone than the host timezone.
    * added a -d parameter (detail) that instructs the MFT input module to include $FN timestamps in addition to $SN
  * **CSV output** Changed the output timezone so it now prints using the -Z definition, so it now supports different output timezone than the host one.
  * **EVTX input** Fixed a bug in where the tool could go into a endless loop in the case where you have a EVTX that is somehow broken and the function get\_next\_event dies. If the tool runs into such occurance it returned an empty timestamp object, that in turn let the tool query for it again, thus possibly getting into an endless loop. Added a counter so the tool tries to get the next event 50 times, otherwise it will die.
  * **log2timeline-sift** Moved the mount command out of the script and into the configuration file
    * Changed the mount command, since there were few errors with the previous one
    * Added an addional check to see if the $MFT file can be directly called (and if so, skip the icat call)
  * **MFT input** Change the mft parser so it doesn't include the $FN timestamps by default (need an additional parameter)
    * Therefore the default behavior of the module has changed. By default it only includes $SN timestamps. An additional parameter to the engine needs to be passed (-d to main front-end or detailed\_time to the engine).

## Version 0.61 (26/09/2011) ##
  * **log2timeline** Small changes to the version printing (now prints just the last portion of the path)
    * Now the engine checks if the format field is set and omits it if its set (to facilitate input modules like CSV that define it).
    * Changed the list modules, added the SAM database readout in the winxp and win7 list files.
    * Created the winsrv list file
    * Added the MFT module to all windows list files (just in case they use a driver that displays the $MFT file)
    * Fixed an issue with the tool not accepting the described format of the offset variable (should be +- int with the appended hms (optional))
    * Added a try/catch around get\_time, http://bugs.log2timeline.net/show_bug.cgi?id=2
  * **L2T\_CSV input** Added an input module that reads the CSV format of log2timeline (done to make it easier to convert CSV files into another format)
  * **extra/bash\_completion** Added a bash\_completion script, stored inside the extra/bash\_completion.d directory (need to copy it manually in the first go)
    * Can make it easier to complete the paramaters to the tool in NIX
  * **l2t\_process** Fixed some timezone settings, or more created some temporary solutions to bug http://bugs.log2timeline.net/show_bug.cgi?id=4
  * **SQLITE output** Changed the schema considerably, along other smaller changes to the SQLite output
  * **TIME library** Fixed a bug in ftk2date (http://bugs.log2timeline.net/show_bug.cgi?id=7)
    * timestamps without ms values are not properly parsed
  * **PREFETCH input** Slightly modified the debug information in the verification step
  * **MCAFEE input** Slight changes in output from the verification routine.
    * Added newline skipping in verification subroutine (code donated anonymously)
  * **ALTIRIS input** New input module to parse the AeXAMInventory and AeXProcessList files from Altiris (donated anonymously)
  * **MCAFEEFIREHUP input** New input module to parse the McAfee FireEpo, FireSvc, FireTray, UpdateLog files (donated anonymously)
  * **MCAFEEHEEL input** New input module to parse the McAfee HIPS event.log (donated anonymously)
  * **SYMANTEC input** New input module to parse Symantec log files (donated anonymously)
  * **MCAFEEHS input** New input module to parse the McAfee HIPShield Log File (donated anonymously)
  * **ANALOG\_CACHE input** New input module to parse the cache log produced by Analog (log parser), user contributed, written by Willi Ballenthin.
  * **FTK\_DIRLISTING input** Bug fixed in the ftk\_dirlist module, the actual file name was repeated in the output... http://bugs.log2timeline.net/show_bug.cgi?id=6
  * **SAFARI input** John Ritchie mad a small bug fix to the module, changing how the timestamp object got defined
  * **IE\_HISTORY input** Fixed a bug in the module. time1 and time2 somehow got mixed up, reversed the order so that time1 is properly defined as the modification time,  instead of being marked as the access time (and vice versa) - thanks to Jamison Bosco for notifying me
    * Small fix, updated the module so that if both time1 and time2 are the same, to join them in a single time

## Version 0.60 (06/06/2011) ##
  * **Log2Timeline library** Created a new library that contains the main engine in log2timeline.  All the funcionality of the tool is moved to this library,  making the front\*ends mostly there to process parameters sent to the tool.  Some core changes made to how the engine is handled, making it necessary to update all the input modules.  The output module all had a constructor, however it was not used that much, so some changes were made to all output modules as well, to transfer some variables needed by some of the output modules.
    * Small changes to the time zone settings.  Instead of using the short name for the timezone, the long name is used throughout the tool
  * **log2timeline** Changed the front\*end to be able to use the new engine.  Removed most of the functionality out of the tool into the new structure.  With the changes to the engine more options have been added to log2timeline, including the possibility of guessing the format of a file (no need to specifically telling the front-end which module to use to parse the file, although it is possible).  Also possible to do recursive searches, making timescanner really unneeded.
  * **timescanner** Changed the front\*end to be able to use the new engine.  It is basically the same tool now as log2timeline, however it will continue to use the same parameters as the older version of timescanner and default to recursive behaviour instead of a single file parsing as log2timeline does.
  * **l2t\_process** Changed the tool so that it removes duplicate entries from the timeline. Also print out few statistics in the end.
    * It checks for suspicious entries indicating timestomping that fall outside the date range (that is entries that have only second precision in the MFT module)
    * Now accepts a file containing keywords, to compare against.  The keyword file should contain a single keyword per line.  The keywords are then compared against every line that passes the date filter. Only lines that have a match against those keywords is printed out.
    * changed parameters slightly, to match with those of the main tool (log2timeline)
    * Added a simple scatter plot creation. Only applicaple if you are parsing the MFT. The scatter plot takes all files that are stored inside the windows/system32 directory and plots the MFT numbers on X\*axis and creation time (both $SI and $FN) on the Y\*axis, to quickly spot outliers in the data set that might be indication of a malware.
    * When the scatter plot is drawn a simple process is run to detect outliers in the dataset and print those
  * **skype\_sql INPUT** Added a new input module that parses the main.db, the SQLite database that belongs to Skype.  Basic module that parses only basic entries from the db, later versions will parse the database in more details.
  * **PreProcessing** Added a pre\*processing library.  Now it is possible to extract information gathered from the drive before the tool starts.
  * **win\_sysinfo PreProc** New module in the pre\*processing library.  A simple library that extracts the hostname of the machine and prints the timezone information before
  * **user\_browser PreProc** New module in the pre\*processing library.  A simple library that goes through each user profile searching for the default browser of that particular user.  The information is both printed on screen and then used in the browser input modules (to indicate whether or not this is the default browser of that particular user)
  * **MFT input** New input module that parses the $MFT file (NTFS filesystem), ported from the tool analyzeMFT written by David Kovar
  * **NTUSER input** Removed the userassist input module and replaced it with a NTUSER one (better name anyway).
    * The module now contains a recursive scanner, where it begins checking if it can parse the key (has a special parsing capability for a partiular key, and if not, it will print the key's name and LastWritten time (a la regtime).
    * The module will then end by getting deleted entries (method gathered from deleted.pl, written by Jolanta Thomassen and distributed on the SIFT.
  * **SOFTWARE input** New input module to extract timestamps from the SOFTWARE registry hive.
  * **JP\_NTFS\_CHANGE** New input module that takes the output from the tool jp (NTFS Change Log), which is a CSV file
  * **SYSTEM input** New input module to extract timestamps from the SYSTEM registry hive.
  * **SECURE input** New input module to extract timestamps from the SECURITY registry hive.
  * **SAM input** New input module to extract timestamps from the SAM registry hive, along with basic SAM parsing
  * **bug reporting** Added a bug tracking system for the tool, available at bugs.log2timeline.net
  * **xp\_firewall INPUT** Fixed a minor bug in the tool where the seconds got omitted (loosing precision on the date)
  * **CFTL output** Changed the output slightly, adding file name to the output for instance
  * **SIMILE output** Changed the output slightly, adding file name to the output for instance
  * **IIS input** The second parameter was not parsed properly, making the module only accurate to the minute, fixed that.
  * **USERASSIST input** Added one more check in the verify function. There were reports of files that contain the magic value for a registry file, yet the reglibrary was unable to retrieve the root key, making the tool crash
  * **TIME library** Fixed the output of the get\_cur\_time called by the recursive scanner to print the current time.  The problem was representation of the time, could be 23:1:42... not it is fixed so that it is 23:01:42
  * **EVTX input** Made small changes to include a URL pointing to further information about the event, and events in general for Win 2008.
    * Also fixed a small bug where the tool was unable to retrieve text content from an attribute
    * Also added a small translation from AccessList codes to "human readable" form, for file auditing
  * **CSV/TAB output** Changed both modules to use the short time zone name instead of the long one in the output.
    * Removed tab characters from description/title to prevent text to spread over tabs in Excel
  * **MACTIME output** Fixed a small issue when the source type is file
  * **EVT input** Fixed the EVT module, it produced two timestamps per entry, even though both timestamps were the same, now it checks and only includes one if they are the same
  * **TLN/TLNX output** Fixed a small issue when the source type is file
  * **SQLITE output** Fixed a small issue when the source type is file
  * **extra FOLDER** Created a small folder called extra that contains some extra scripts, such as a script to remove the log2timeline from the system
  * **glog2timeline** Removed the glog2timeline GUI, at least for the time being. It has to be ported to the new engine, and until then it is removed.


## Version 0.52 (05/04/2011) ##
  * **MSSQL\_ERROR** A new input module that parses the MS SQL errorlogs
  * **GENERIC\_LINUX** A new input module for generic linux log files, contributed by Tom Webb
  * **ENCASE\_DIRLISTING** A new input module for importing the text file exported from Encase (file listing), it supports the text based export with all columns
  * **L2T\_PROCESS** Added a small tool to process body files with the CSV output, similar behavior as mactime for the mactime body format
  * **MACTIME input** Fixed a problem with the import of mactime timestamps, now the tool groups together timestamps of the same value. This means that when outputting using other modules than mactime there is only one line printed for each timestamp available, instead of always printing four.
  * **Parse::Evtx Library** Updated the EVTX library to version 1.0.7 (with small changes to the source code for it to properly work with L2t)
  * **LOG2TIMELINE** Added a -F or force option to make the tool ignore the verification phase and go ahead to try to parse the file
  * **TIMESCANNER** Changed the format sort, to make generic linux below in format order than syslog
    * Added a small print out before the tool's being run, for logging purposes
    * Changed the default output module to CSV instead of mactime
  * **TIME library** Added a function called get\_cur\_local\_time to get the current local time (in human readable format)
    * Added a function encase2date to handle the date objects from the Encase file export
  * **BINREAD library** Added a small check to see if we've reached the end of the file during unicode reading
  * **EVTX input** Added information from the data tag into the output
  * **BUILD** Updated the RPM spec file, unSpawn sent me an updated file, since I haven't maintained it for a while. Verified by unSpawn to work on a CentOS 5
    * Added a spec file for openSUSE, built by Greg Freemyer

## Version 0.51 (14/12/2010) ##
  * **APACHE2\_ACCESS input** A new input module that parses the Apache2 access logs, written by Willi Ballenthin with slight modifications made by Kristinn
  * **APACHE2\_ERROR input** A new input module that parses the Apache2 error logs, written by Willi Ballenthin
  * **SYSLOG input** A  new input module that parses syslog message, written by Willi Ballenthin
  * **SAFARI input** A new input module that parese Safari browser history plist files, submitted by Hal Pomeranz
  * **FTK\_DIRLISTING** A new module that reads the input from the CSV file FTK Imager creates when exporting directory listing
  * **WMIPROV input** A new input module that parses the wmiprov.log file in Windows
  * **TAB output** A new output module that outputs the data in a tab delimited file
  * **USERASSIST input** Changed the module from UserAssist to really a NTUSER.DAT module.  The module no incorporates lot of other registry keys

> such as MRU keys, mountpoints, etc. (more can be added as needed)...
  * **LINUX\_SERVER** A new list file that contains possible modules to use against a Linux server
  * **MACTIME input** Added a more rigourous test into the verification phase, since the input module seem to have found some false positives
    * Corrected a small bug, where the size value didn't get properly verified
    * Corrected a small bug, where the crtime ended up being the only one saved...
  * **TIME library** Fixed a minor error in the exif\_to\_epoch function, badly formatted dates caused the tool to die (for instance a month value of zero)
    * Fixed a minor bug in the pdf\_to\_epoch function where badly formed offset caused the tool not to correctly parse the date object
    * Fixed a minor bug where a date in EXIF causes the tool to stop, the second parameter is ssz, instead of the expected ssZ,
    * Added a function to parse MS\*DOS 32 bit timestamps
    * Added a function to calculate integer value from abbreviated month names (jan,feb,...)
    * Added a function to calculate Epoch value from timestamps as they appear in FTK exported CSV files
    * Hal Pomerans added a function to convert the Mac based timestamps to Epoch, mac2epoch
  * **OPERA input** Sometimes an additional new line character got included with the date object, removed it
  * **IEHISTORY input** Fixed two minor bugs when header data was filled with garbage and cache directory empty (not display those characters nor headers)
  * **SOL input** Fixed a minor bug where newline characters were removed from the description field
> > Fixed a minor bug where an infinite number within a variable name (not date object) can lead to date errors
  * **TIMESCANNER** Added information about the called directory inside the timestamp object when timescanner used with the -m parameter (used so that output modules can remove the path from the file name if they choose to do so)
    * A small addition of a check, see if the t\_line variable is defined, otherwise skip the check (JLR added)
    * Added information about the -f option in timescanner to the man page and help file
    * Added the option of -e|--exclude STRING, where STRING is a list of files to exclude from the scan.  It is possible to parse in a regular expression inside this variable (that is a comma separated list of files to exclude)
    * Changed the version information, so that timescanner uses the same version as log2timeline does
  * **MACTIME output** Modified mactime output module so that it removes the path of the originally called directory when timescanner is called with the -m parameter (to get directories correct in the output)
    * Added a small change, where to exclude the type of timestamp when we are dealing with a source of "FILE"
  * **COMMON library** Added a sub routine that replaces certain characters to pattern or vice versa.  To be used with output modules that need to change file paths
    * Changed the way the output or list of modules is printed (to align the output)
  * **TLN output** Modified the output module so that it removes the path of the originally called directory when timescanner is called with the -m parameter (to get directories correct in the output)
  * **OXML input** Fixed a minor bug in the module that caused timescanner to die if the document got past the verification stage, yet didn't have a file describing the relationship between XML documents (the .rels).
    * Removed the die clause from the module to prevent timescanner from dying when parsing files, when encountering errors
    * Added eval sentence around each parsing of OXML files, since there have been cases where the tool was unable to parse a XML file and died
  * **WIN library** Added some more GUID's in the list
  * **CSV output** Modified the output a bit to eliminite all instances of an additional , (commas) that might be in the output
    * Also modified and updated the module to properly display filenames with paths (if defined with -m and timescanner used)
    * Modified the output sequence, there was a bug causing the header not being consistent with the output body
    * Modified the Date portion, changed from "Wed 03 December 2001" to "03/12/2001" (easier parsing by spreadsheet applications)
  * **RESTORE input** Added few checks to see if there is an empty restore folder, and no restore file, so the tool doesn't die (added by JLR)
    * Removed the remaining die clauses from the module to prevent timescanner from dying when parsing files, when encountering errors
  * **FIREFOX3 input** Removed the die clause from the module to prevent timescanner from dying when parsing files, when encountering errors
  * **WIN\_LINK input** Removed the die clause from the module to prevent timescanner from dying when parsing files, when encountering errors
  * **MACTIME output** Modified the output, remove all occurances of ; and replace it with _.  When saving the mactime output as a .csv file and open it up in Excel (or other spreadsheet applications) they automatically treat ; as a separator, making some fields sometimes dissapear when splitting the text field into columns_

## Version 0.50 (30/06/10) ##
  * **VOLATILITY** An input module created by Julien Touche has been added that parses the output from psscan2 module of the Volatilty framework
    * Updated the input module to take advantage of the new timestamp object
    * Modified the module to both use the psscan and psscan2 output
    * Modified the module a bit to fix some issues with multiple date objects
  * **TLNX output** Created a new output module that outputs in the TLN format, using XML as the output method
  * **BEEDOCS output** Created a new output module that outputs in a TDF (tab delimited file) that can be imported into BeeDocs for visualization
  * **log2timeline** Modified log2timeline so it can handle the new t\_line timestamp object
    * Modified the man page (the pod section) to reflect the changes made to the framework
    * Added the option of -n to define the host name
    * Modified the -c option, which is ambigious (both -c => calculate and check).  Now -c means calculate and -u or -upgrade means the version checking
    * Modified the version checking, added check for a proxy settings, using environment variables (no manual proxy settings supported yet)
  * **timescanner** Modified timescanner to accept list of input modules that it will use during it's scan. The addition is implemented so that the user can supply -f LISTNAME where LISTNAME is either a name of a .lst file (predefined lists of known input modules), see the available files by issuing -f list. LISTNAME can also be the name of the module to scan, or a list of them (comma separated) (see man for further detail)
    * Added support for the new timestamp with the possibility to use the old timestamp object (backward compatibility)
    * Added a field, if a file has been successfully parsed, no more checks are made against it
    * Sort the input modules run agains files, exif is always the last
    * Made some optimization changes to the tool
    * Added the option of -n to define the host name
  * **glog2timeline** Upgraded so it can use the new timestamp object
    * Added the limited proxy support (using env, not manually set)
    * Fixed a typo in the GUI, sucpect became suspect (thanks Chris Shanahan for pointing this out to me)
  * **TLN output** Modified the TLN output module so that it can handle the new timestamp object
    * Added a check to see if the timestamp is of zero value (or less), not to print those timestamps
  * **TIME library** Added the fix\_epoch function back into the tool, upgraded it so that it considers DST
    * Fixed the epoch2iso function
    * Added a check to hash\_to\_date function to fix a bug in the mcafee input module
    * Fixed an issue with date calculations in the pdf\_to\_date function, now date addition/subtraction is done through datetime, not by simple calculations which often lead to errors (especially when offsets in dates caused the day to cross an illegal date, such as 31st of a month that only has 30 days in it)
  * **BINREAD library** Added the function read\_ascii\_magic that reads an ascii string until it hits either the maximum amount of entries, the null value or a predefined magic value that can be of arbitrary length.
  * **COMMON library** Added few more options to the get\_username\_from\_path function.
  * **MACTIME output** Upgraded the output module so that it can handle the new timestamp object
  * **ALL input modules** Modified the verification phase, to help speed up verification
  * **RECYCLER input** Upgraded the input module to use the new timestamp object
  * **EVT input** Upgraded the input module to use the new timestamp object
    * Added a small check to see if there is a reference to a KB article
    * Changed the usage of , to - to avoid confusion with the CSV output
    * Added a support for KB article check, and to add the KB link to the URL field
  * **EVTX input** Upgraded the input module to use the new timestamp object. Fixed a bug in the library where timestamps would appear as zero value
  * **EVTX Library** Updated to the latest version, 1.0.5
  * **CHROME input** Upgraded the input module to use the new timestamp object
  * **EXIF input** Upgraded the input module to use the new timestamp object
    * Added more checks to validate if the file is a XML file (skip if it is, XML files tend to take up awful lot of memory)
  * **FF\_BOOKMARK input** Upgraded the input module to use the new timestamp object
  * **FIREFOX3 input** Upgraded the input module to use the new timestamp object
  * **IEHISTORY input** Upgraded the input module to use the new timestamp object
    * Also fixed a bug where some timestamps are written using Local timestamp.  That is to make the iehistory file more location aware. The module will now check the location of the index.dat file to compare it to predefined set of locations.  This is done since some timestamps are stored in local timezone, such as the weekly history files, whereas others are stored using UTC, like the master history file.
    * Added path checking to verify which type of index.dat file we are dealing with and assigning the date and timestamps accordingly
    * A bug fix, sometimes additional characters were added to the printing of header information (reported by Stefan Kelm)
  * **IIS input** Upgraded the input module to use the new timestamp object
  * **ISATXT input** Upgraded the input module to use the new timestamp object
  * **MACTIME input** Upgraded the input module to use the new timestamp object
  * **OPERA input** Upgraded the input module to use the new timestamp object
  * **OXML input** Upgraded the input module to use the new timestamp object
    * Changed the output a bit, to add more context to it.
    * Fixed a minor bug, causing timescanner to spew additional timestamps into objects.  That is an array wasn't initialized, causing timescanner to reuse the array that stored the timestamps extracted from previous documents.
  * **PCAP input** Upgraded the input module to use the new timestamp object
  * **MCAFEE input** Upgraded the input module to use the new timestamp object
  * **PDF input** Upgraded the input module to use the new timestamp object
  * **PREFETCH input** Upgraded the input module to use the new timestamp object
    * Fixed few parts of the input module, to make it more optimized, reduced the time it took to run by half
  * **RECYCLER input** Upgraded the input module to use the new timestamp object
  * **RESTORE input** Upgraded the input module to use the new timestamp object
  * **SETUPAPI input** Upgraded the input module to use the new timestamp object
  * **SOL input** Upgraded the input module to use the new timestamp object
  * **SQUID input** Upgraded the input module to use the new timestamp object
  * **TLN input** Upgraded the input module to use the new timestamp object
    * Added support for the optional 7 fields (added TZ and Notes)
  * **USERASSIST input** Upgraded the input module to use the new timestamp object
    * Fixed a small bug, if a username is not found the module called a wrong function to guess the username from path
  * **WIN\_LINK input** Upgraded the input module to use the new timestamp object
    * Changed the way volume serial numbers are presented from decimal to hex (tool consistency)
  * **XPFIREWALL input** Upgraded the input module to use the new timestamp object
  * **CEF output** Modified the output module so that it can handle the new timestamp object
  * **CFTL output** Modified the output module so that it can handle the new timestamp object
  * **CSV output** Modified the output module so that it can handle the new timestamp object
  * **MACTIME\_L output** Modified the output module so that it can handle the new timestamp object
  * **SIMILE output** Modified the output module so that it can handle the new timestamp object
  * **SQLITE output** Modified the output module so that it can handle the new timestamp object
    * Changed all references to BLOB to TEXT, easier to index and search through
    * Removed the host table, since it was unnecessay
  * **TLN output** Modified the output module so that it can handle the new timestamp object

## Version 0.43 (06/04/10) ##
  * **MCAFEE input** Fixed a small bug where the input module would not parse the month value if it was only a single digit
  * **timescanner** Temporary fix was added, excluding index.dat files that are inside daily or weekly history files
  * **EVTX input** Fixed a flaw with the EVTX library, where timestamps appear as zero value
  * Created an Ubuntu repository to make the installation process easier.  I created Debian packages for those modules that do not have any packages as of yet in the official Debian repository.
  * Log2timeline has also been included in the CERT forensics repository (for Fedora).  So add the CERT repostory to your Fedora workstation (http://www.cert.org/forensics/tools/) and issue yum install log2timeline.  All dependencies should be fixed as well.
  * **FIREFOX2 input** Added a Firefox 2 input module to parse the history.dat mork file
  * **OXML input** Fixed a minor bug, uninitialized array that caused timescanner to reuse timestamps from previous documents

## Version 0.42 (05/03/10) ##
  * **MCAFEE input** Added an input module that reads the log files produced by the McAfee antivirus product
  * **PDF input** Added an input module that reads PDF metadata (not XMP) to extract timestamps from PDF documents
  * **OPERA input** Fixed a minor bug in the Opera input module that lead to the fact that every Opera Global History file wasn't verified (and therefore not parsed). Also fixed a minor bug that caused username in some cases not to be properly printed
  * **USERASSIST input** Small modification to the output of the tool when the new version of NTUSER.DAT file is used
    * Added a GUID check to the older XP format of userassist keys
    * Added a title or shorted description field of the user assist keys
  * **CSV output** Modified the CSV output, only one time per entry and a type field added (more like the original mactime)
  * **log2timeline** Added a new field called notes to the timestamp object to include additional information about the event in question
  * **EVT input** Added a link to eventid.net for event description in the note field of the timestamp object
  * **SQLITE output** Modified the SQL structure as well as how the data is included in the database field
  * **TLN output** Properly coded the TLN field so that it contains one entry per timestamp (older version used only crtime)
    * Modified and updated the code to reflect the current state of the standard (updates to the standard were made)
    * Using both optional fields, that is the TZ and Notes field for further describing the event in question
  * **XPFIREWALL input** Fixed an issue with an almost empty line (containing only space/s
    * Added a check for the time zone information (to gather and record time zone settings to correct timestamps)
  * **PREFETCH input** Updated the code a bit, making the text clearer as well as to simplify the date used, now only the time parsed out of the prefetch file is used as a timestamp as well as adding the extraction of the name of the executable to be parsed out of the prefetch file
    * Added more detailed information retrieved from the Prefetch file, extract loaded DLL names and print it along with the prefetch information
    * Added support for Windows Vista/Win7/.. Superfetch files. The version of the prefetch file is determined automatically or newer version of the Windows operating system (the default behaviour is the XP prefetch file)
    * Fixed a small off by one bug (one prefetch file was not processed)
    * Fixed a small bug, causing Prefetch information not to be included in timescanner output
  * **SOL input** modified a small bug in the assignments of date values, not all timestamps were properly set when a timestamp was found within the sol file
    * Another minor bug was fixed, the value of TRUE and FALSE in boolean values was switched
    * Modified the presentation of information, that is to translate double numbers that represent date objects into human readable format
    * Added path information taken from the main module (-m parameter) to include with the file name
    * Added another date check in the output (to modify epoch time to human readable one in the output format)
  * **FIREFOX3 input** Removed a false fix\_epoch statement, there is no need to fix the epoch value
  * **OXML input** Added path information taken from the main module (-m parameter) to include with the file name
  * **EXIF input** Added path information taken from the main module (-m parameter) to include with the file name
  * **WIN library** Added few more GUID's that are XP specific as well as others that are third party related and Vista/Win 7 specific
  * **CFTL output** Added few more text replacements so the output is properly imported into CFTL
  * **TIME library** Fixed a bug in the sol\_date\_calc function, uncorrectly calculated timestamps from the time value passed to it
    * Removed the fix\_epoch function, since it is not necessary and can lead to false results
    * Added an option to epoch2text to print the time in the use supplied time zone
    * Added an option to calculate dates from PDF documents (to accomodate the PDF input module)
    * Added a check to sol\_date\_calc to see if the variable passed in is higher than a fixed number (epoch from a date in 1995) and less than the current date plus 20 years
  * **log2timeline** Added a check to see if the inode value was empty, and then fill it up with the correct value
    * Added the option of -calculate to calculate md5 sum of the file in question (included in the md5 part of the timestamp object)
    * Changed all references to \ to /, to make all paths more consistent
    * Added a check to see if -m was used then the value of it would be added as a path parameter to the input module (to include it in the filename path)
  * **timescanner** Added a check to see if the inode value was empty, and then fill it up with the correct value
    * Added the option of -calculate to calculate md5 sum of the file in question (included in the md5 part of the timestamp object)
    * Changed all references to \ to /, to make all paths more consistent
    * Added a check to see if -m was used then the value of it would be added as a path parameter to the input module (to include it in the filename path)
    * Added a counter, showing how many files were processed by the tool (printed in the end of the run count alongside the run time of the tool)
  * **most input modules** Changed the verification phase so that it starts by checking if this really is a file (-f) instead of just checkingif the input is not a directory or if it exists (-e).  There was problems when trying to parse FIFO or other types of non standard files. This caused problems in Vista/Win 7 images that made timescanner run to a halt while trying to verify the structure.
  * **Parse:Evtx** Updated the Parse::Evtx library by Andreas Schuster to version 1.0.3

## Version 0.41 (15/01/10) ##
  * **CHROME input** Added a new input module for Chrome browser history
  * **OPERA input** Added a new input module for Opera history files (both DIRECT and GLOBAL history files)
  * **CEF output** Added an output module for the Common Event Format (CEF)
  * **FIREFOX BOOKMARK** Added a new input module for Firefox bookmark file
  * **EVTX** Added a new input module for Windows Event Log files (EVTX) for Windows Vista and Win 7, based on the EvtxParser libraries by Andreas Schuster
  * **output modules** Added a constructor to all the output modules to include the possibilty to send parameters to the output modules
  * **SOL input** Almost rewrote the entire parser for SOL to correct several problems with the input module.
  * **FIREFOX3 input** Few bug fixes in the Firefox 3 module, missing some fields in the t\_line hash as well as to add the host parameter
    * Modified the verification process so that instead of trying to select a value from moz\_places a list of all available
    * Added information from the moz\_items\_annos and moz\_bookmarks table to include bookmark information from Firefox 3
  * **USERASSIST input** added a missing field in the t\_line hash as well as to fix a minor bug that caused UserAssist input module not to parse any file when timescanner was used.
    * Added support for Windows Vista and newer operating systems, based on an article by Didier Stevens in IntoTheBoxes magazine (1q2009)
  * **WIN library** Added a new library called Win (Log2t::Win) which will contain various information extracted from a Windows system.  This first version only contains a list of known GUIDS that can be extracted and used by various modules
  * **MACTIME output** Fixed a small bug, where the pipe symbol might be a part of the name part (change all | to ::pipe:: before outputting)
  * **MACTIME\_L output** Fixed a small bug, where the pipe symbol might be a part of the name part (change all | to ::pipe:: before outputting)
  * **COMMON library** Added a function to "guess" the username from the path of the file
  * **CSV output** Modified the output slightly, dates come now first, and they are in a human readable format instead of Epoch tables is selected, and it is checked whether or not moz\_places exists in that list (the other method resulted in various error messages when timescanner found a SQLite database file that did not contain moz\_places
  * **TIME library** Added a few checks in the exif\_to\_epoch function to accomodate new behaviour in exiftools 8.00
    * Added the offset check, and check for negative offsets sent to the input module by Exif
  * **EXIF input** Modified the way the information is presented a bit, moved the name of the metadata variable in front of the text to make it more clear what was being referred to as well as to add the group name.
    * Removed few tags from the reading, such as ZIP (recursive scan through ZIP files) as well as File (don't care about filesystem time)
    * Also added a check if the input module is parsing PE files to make them more readable
  * **update\_log2timeline** Added a bash script to automatically update the tool.  It fetches the binaries from the web site, verifies the MD5sum of the file and then extracts and installs it.  The script has a switch to indicate that the user want's to download the nightly builds instead of the newest released version.
  * **SETUPAPI input** Fixed a bug in the SetupAPI input module that caused all the lines in the body file to contain the first found date in the file
    * Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
  * **log2timeline** Added an extra field to the t\_line hash in the front\*end, the field filename that includes the original file name.
    * Added a call to the constructor new() of the called output module, and passed along the array ARGV
> > > Modified the check for new version function.  Added a text indicating that the user can use the tool update\_log2timeline to update the tool automatically
    * Updated the man information (the pod)
    * Added a switch, **d for debugging information (debugging is sent to input modules as well)
  ***glog2timeline**Added an extra field to the t\_line hash in the front\*end, the field filename that includes the original file name
  ***timescanner**Added an extra field to the t\_line hash in the front\*end, the field filename that includes the original file name
    * Added a call to the constructor new() of the called output module, and passed along the array ARGV
    * Added a printout in the end of run, indicating how long it took for the tool to complete it's run (an indication that the tool completed successfully as well)
    * Added a check to see if local timezone was chosen.  If the local timezone is chosen it is printed on the screen (that is what the tool detects as the local timezone)
    * Increased the verbosity of timescanner**h to include the options of the tool
    * Added a small check to see if a file is a symbolic link, don't test symbolic links (the tool ends up in a loop, checking the same file again and again
    * Added few more debugging information and a check to invoke debugging in input modules if called with -vv
  * **IEHISTORY input** Added a check for invalid HASH table reference
  * **IIS input** added a missing field in the t\_line hash
    * Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
    * In some IIS log file there isn't a field called date, it is instead defined in the header of the file, check for those files
  * **ISATXT input** added a missing field in the t\_line hash
    * Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
  * **MACTIME input** added a missing field in the t\_line hash
  * other minor improvements
    * Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
  * **OXML input** added a missing field in the t\_line hash
  * **PCAP input** added a missing field in the t\_line hash and added TCP sequence number to the output (request)
  * **RECYCLER input** added a missing field in the t\_line hash
  * **PREFETCH input** added a missing field in the t\_line hash
  * **SQUID input** added a missing field in the t\_line hash
    * Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
  * **RESTORE input** added a missing field in the t\_line hash as well as to change the dates provided.  Now the only date that is read is the installation of the restore point, instead of including the atime,ctime and mtime of the file itself (that one is provided with fls)
  * **TLN input** added a missing field in the t\_line hash
    * Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
  * **WIN\_LINK input** added a missing field in the t\_line hash
  * **XPFIREWALL input** added a missing field in the t\_line hash

> > Modified the verification, reading the file as binary to only scan the first portion of the file (instead of trying to read a line from a large file)
    * Added TCP seq numbers into the output

## Version 0.40 (25/11/09) ##
  * **CFTL output** Fixed few bugs in the cftl.pm output module, didn't work in the current CFTL version without these modifications

> (has been verified to work with CFTL pre\*relase version 1.0)
  * **EXIF input** Fixed a bug in the exif input module, there was a problem with the format of date variables read by ExifTool library.
  * Added a format string to force the date format to be the same.
    * **glog2timeline** Modified the GUI, glog2timeline to make it feature compatible with the CLI interface, added:
      * Simple menu structure
      * Added the possibility to add timeskew information
      * Added the possibility to prepend text to output (a la -m)
      * Added the possibility to perform most of the operations through the menu structure
      * Added the possibility to check for latest version (version check)
      * Added a simple progress bar and information about the artifact being processed **more work needs to be done here**
      * Added the possibility to define the timezone of the suspect drive (list all available timezones sorted, using UTC as the default zone)
    * **List library** Modified the name of the Log2t::List library to Log2t::Common so that the library can be used for all common functions
> > that are shared between more than one module (instead of only focusing on listing directory entries)
    * **BinRead library** Fixed few bugs in the BinRead library that dealt with Unicode reading
    * **WIN\_LINK input** Modified the text output of win\_link input module, to make the output more readable
    * **RECYCLER input** Modified the recycler.pm so that it reads the recycle bin directory instead of the INFO2 file.  Added the possibility
> > to read $I files as well (the newer format as used in Vista, Windows 7 and later operating systems from Microsoft).  The
> > new input module reads the directory and determines if it is examining the older or newer version of the recycle bin and parses
> > accordingly
    * **timescanner** added a banner to timescanner, giving people warning about the tool, since there have been reports of it being unreliable in
> > parsing all files that it should be able to do.  This banner will stay until the tool has been fixed (coming version)
    * **timescanner** added the possibility to add timezone information, as well as to add a timezone related functions to be used by libraries
    * **timescanner** Fixed a bug, forgot to close the input module after parsing an artifact (creating some problems)
    * **USERASSIST input** fixed a bug in the userassist module.  It crashed if it encountered a registry file it was unable to load (eg NTUSER.DAT.LOG),
> > added a check for that, so timescanner will not die when he reaches such a file
    * **FIREFOX3 input** added an extra check in the verify routine to double check that we are in fact examining a FF3+ history database, now connecting
> > to the database to see if there is a moz\_places table there before proceeding.  Added few error message checks as well, to improve the error handling
> > of the verification. Fixed a bug where Firefox 3 history files were not included in the timescanner tool (had to do with the verification and improper
> > check if the database was locked)
    * **log2timeline** Added the possibility to define the timezone of the suspect drive (**z ZONE parameter). The default timezone is local
> > (that is the local timezone of the analysis station).  This affects the timesettings of all artifacts found on the system and adjusts it
> > accordingly).  The option of "**z list" will print out a list of all available timezones that can be chosen.
    * **OXML input** Modified the verify function, only read the ZIP header if the magic value of the file indicates that this is a ZIP file (reduces time
> > needed for the verification function, and therefore reduces the time needed for timescanner)
    * **Common library** Added constants to the Common library (BIG\_E and LITTLE\_E) that are shared with other libraries and modules
    * **input modules** changed all input modules that call the BinRead library so that they initialize the endian.  This fixes a bug in
> > timescanner, since some input module set the BinRead to big endian, which is not changed back when another input module that reads in a little endian
> > was started (making verification and all uses of binary reading wrong, leading to the fact that timescanner did not parse the files)
    * **Time library** Added a function called fix\_epoch to take an epoch value, and use the supplied timezone settings to modify it to UTC
    * **input modules** Modified the input modules so that they all now output the timezone information in UTC
    * **Setupapi input** Modified the SetupAPI input module, considerable changes made in the way that the file is parsed
    * **log2timeline** All input modules now output their time in UTC, irrelevant of the method of storing time entries.  This makes it vital
> > to add a parameter to define the timezone of the suspect drive
    * **evt** Added a new input module that is capable of parsing Windows 2000/XP/2003 Event Log files (mostly rewrite of evtparse.pl by Harlan Carvey)

## Version 0.33b (15/09/09) ##
  * Fixed a bug in iehistory.pm, small bug when reading index.dat files that contain no history
  * Fixed a bug in iehistory.pm, directory names not correctly read as well as header information (sometimes these

> values contained unreadable characters)
  * Fixed a bug in mactime.pm input module, small bug in the validation, all mactime files failed
  * Fixed a bug in the tln.pm input module, files weren't validated (all files failed validation)
  * Updated the List.pm library so that the input modules and output modules are sorted when the option
> of **f list or**o list is used

## Version 0.32b (10/09/09) ##
  * Fixed few bugs in both iehistory.pm and userassist.pm
  * Created a new library, Network.pm to include information about network traffic
  * Added an input module for parsing SetupAPI log file in Windows XP
  * Added an input module for parsing Flash cookies, or Shared Object Libraries (SOL) from Macromedia
  * Updated few libraries (BinRead, Time)
  * Added an input module for parsing XP Firewall logs
  * Added a new feature into log2timeline, version checking.  Use logtimeline **c to check if you have the
> latest version installed of the tool**

## Version 0.31b (07/09/09) ##
  * Added a format file to read EXIF data
  * Added a new tool called timescanner to recursively scan through directories, searching for
> artifacts to parse (testing against all supported artifacts)
  * Added an output module to output in a CSV file
  * Created a Makefile.PL to provide a different mechanism for installing the tool.  The script install.sh is
> no longer used, and all input modules are now copied to a Perl library directory, along with other Log2t library files.
> The use of "use lib '/usr/local/share/log2timeline/lib'" has been removed from all input modules since it is no longer needed
> and all front\*ends have been adjusted to accommodate the new setup
  * Created a new library, List.pm (Log2t::List) to list up all input and output modules

## Version 0.30b (02/09/09) ##
  * Fixed a bug in the sqlite output plugin, escape sequence not properly inserted
  * Small changes made to the restore point format file
  * GUI, glog2timeline added to provide an alternative method to create body files, so now
> there are two possibilites to use the modules, by using a CLI version and a GUI
> (GUI is written using perl\*gtk2 meaning it will propably only work in Linux). This first version of the
> GUI is very limited, more to show the possibility to have a GUI, will be fixed in later versions
  * Modified the sqlite output plugin, changed the SQLite database structure to accomodate
> a scheme that will be later used by a graphical front\*end
  * Created the first version of the PCAP format file (will be upgraded later)
  * Changes made to all format files to speed up processing, optimization changes made and
> modifications to the flow of information from main script to and from the format and
> output files (to speed things up)
  * Modified the log2timeline main script to accomodate the optimization changes made in
> the format files (references used considerably more instead of passing arguments)
  * Removed common functions from the log2timeline main script and included them in seperate
> libraries that are stored in the library path.  This creates a way for other front\*ends
> to use the format files, such as the GUI or a scanner
  * Modified format files so that they use the libraries instead of calling parent function (main script)
  * Created a BinaryRead library file to make reading binary files easier (code reuse really)
  * Added a new output module, an XML file that can be read by SIMILE timeline project to visually represent timeline data (this is just the XML file, work needs to be done to create HTML documents or other web sites to present the data)
  * Added an output module to output in the XML format that the tool CFTL (CyberForensics TimeLab) can use to visually represent timeline data
  * Added a format file to parse Internet Explorer history file, index.dat
  * Modified log2timeline so it removes footer from files when appending to timelines

## Version 0.22b (10.08.2009) ##
  * Added format file for TLN format, that is body files that are built using the TLN
> or timeline format
  * Added format file for OpenXML documents, such as docx, pptx and other documents created
> by Microsoft Office 2007.
  * Added iso2epoch function to log2timeline for convertion of iso 8601 date formats to
> epoch (for timeline)
  * Added format file for mactime input
  * Added format file for ISA text export (that is query into the ISA firewall/proxy for a certain
> web traffic, copy all contents to the clipboard, save to a file and parse through log2timeline.
> One warning about this format file, it has only been tested on one particular ISA server so no
> guarantee about the accuracy of this format file (until further tested)
  * Added the option to output directly to a file, that is to let the tool output to a file instead
> of just using STDOUT and STDERR
  * Added an output plugin for dumping records into a SQLite database

## Version 0.21b (07.08.2009) ##
  * Fixed few bugs in the win\_link.pl format file:
> > Unicode characters were not printed correctly
> > Empty strings appeared on few places
> > No verification that the file was truly a LNK file (no check for magic value)
> > Control characters were printed out with the path name
> > Path name not correctly read, size of strings included in printout
> > Added distinction between path name and other paths and strings (relative path,
> > working directory, comments and cmd line arguments)
  * Added verification code to the firefox3 format file
  * Fixed few print settings in log2timeline, print error msg to STDERR as well as sending the

> ARGV array into the format files, to add the possibility to have parameters/options sent to
> format files
  * Added format file for IIS log files (W3C)
  * Added output file TLN (timeline format) from H. Carvey, five field format
  * Modified format files so that they include necessary information for TLN format output
  * Added parameter reading to all format files, parameters can now be sent to format files
> and most of them accept some (for additional info needed for TLN creation for instance)

## Version 0.20b (04.08.2009) ##
  * UserAssist: username is gathered from NTUSER registry and added to timeline
  * Seperated the output to a special output file, created a structure to output
> in different modes (other than mactime format)
  * Created the mactime output file (default behaviour)
  * Created the mactime\_l output file, for legacy output (older versions of TSK), fixed
> the older version of the legacy output which did not work correctly (not using the correct
> legacy format)
  * Minor bug fix in the install.sh (the install script)
  * Minor bug fix in the log2timeline script as well as adding an additional check
> before calling format files (check to see if dir or file exist prior to calling script)
  * added Firefox3 format file

## Version 0.12b (31.07.2009) ##
  * pod created for further description of tool and to print help messages
  * print\_help function deleted from main script and pod2usage used instead
  * man page created for the tool (using pod2man)
  * minor changes to the prefetch format file
  * format file for Windows shortcuts added (win\_link)
  * format file for Windows INFO2 (recycle bin) added

## Version 0.11b (20/07/2009) ##
  * Fixed few minor bugs in tool

## Version 0.1b ##
  * First beta release of tool