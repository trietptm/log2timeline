# Format #

By default log2timeline uses the l2t\_csv output format. It is a simple CSV (comma separated) file with 17 fields.

The first line of the CSV file is a header, containing the name of each field, followed by each timestamped entry. Each line in the CSV file refers to one timestamped entry, which means that each timestamp object may be expanded to several lines.

The header is:

```
date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
```

# More Detailed Description #

A more detailed description of each of the fields and their meaning:

  1. **date**: The date of the event, in the format of "MM/DD/YYYY" (n.b this might get changed in a future version to YYYY-MM-DD, but for now this will stay this way).
  1. **time**: time of day, expressed in a 24h format, HH:MM:SS (in future versions this may change to include ms values in the format of HH:MM:SS.ms)
  1. **timezone**: The name of the timezone used as the output timezone, or the chosen timezone of the input file if no output timezone was chosen.
  1. **MACB**: MACB or legacy meaning of the fields, mostly for compatibility with the mactime format.
  1. **source**: Short name for the source. This may be something like LOG, WEBHIST, REG, etc. This field name should correspond to the type field in the TLN output format and describes the nature of the log format on a high level (all log files are marked as LOG, all registry as REG, etc.)
  1. **sourcetype**: More comprehensive description of the source. This field further describes the format, such as "Syslog" instead of simply "LOG", "NTUSER.DAT Registry" instead of "REG", etc.
  1. **type**: type of the timestamp itself, such as “Last Accessed”, “Last Written” or “Last modified”, etc.
  1. **user**: username associated with the entry, if one is available.
  1. **host**: hostname associated with the entry, if one is available.
  1. **short**: short description of the entry, usually contains less text than the full description field. This is created to assist with tools that try to visualize the event. In those output the short description is used as the default text, and further information or the full description can be seen by either hovering over the text or clicking on further details about the event.
  1. **desc**: description field, this is where most of the information is stored. This field is the full description of the field, the interpreted results or the content of the actual log line.
  1. **version**: version number of the timestamp object. Current version is 2.
  1. **filename**: filename with the full path of the filename that contained the entry. In most input modules this is the name of the logfile or file being parsed, but in some cases it is a value extracted from it, in the instance of $MFT this field is populated as the name of the file in question, not the $MFT itself.
  1. **inode**: inode number of the file being parsed, or in the case of $MFT parsing and possibly some other input modules the inode number of each file inside the $MFT file.
  1. **notes**: Some input modules insert additional information in the form of a note, which comes here. This might be some hints on analysis, indications that might be useful, etc. This field might also contain URL's that point to additional information, such as information about the meaning of events inside the EventLog, etc.
  1. **format**: name of the input module that was used to parse the file. If this is a log2timeline input module that produced the output it should be of the format Log2t::input::NAME where name is the name of the module. However other tools that produce l2t\_csv output may put their name here.
  1. **extra**: additional information parsed is joined together and put here. This 'extra' field may contain various information that further describe the event. Some input modules contain additional information about events, such as further divide the event into source IP's, etc. These fields may not fit directly into any other field in the CSV file and are thus combined into this 'extra' field.