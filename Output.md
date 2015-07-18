# Output Mechanism #

Each event that is parsed is represented internally as a timestamp object, which is currently implemented as a Perl hash. This timestamp object can contain multiple timestamps, since some entries in log files or other events may contain information about more than one timestamp, for instance a timestamp for a file in the NTFS filesystem contains at least eight timestamps, all of which are stored inside a single timestamp object.

This makes the tool capable of easily outputting the data in any format that the user needs. It is very simple to create a new output module that takes each of these timestamp objects and formats it according to some output standard.

To get a complete list of the currently supported outputs use "_log2timeline_ _-o_ _list_".

The two most common output modules are:
  * [l2t\_csv](l2t_csv.md) (the default output mechanism)
  * [mactime](Bodyfile.md)

## Timestamp Object ##

Internally each event is described as a timestamp object that is implemented as a Perl hash.

The hash is created inside each input module and then passed as a reference to the main engine, which further adds some values to it before passing the reference along to the output module for formatting.

The timestamp object is called _t\_line_ and consists of the following fields:
```
 %t_line {        
       time
               index
                       value
                       type
                       legacy
       desc
       short
       source
       sourcetype
       version
       [notes]
       extra
               [filename]
               [md5]
               [mode]
               [host]
               [user]
               [url]
               [size]
               [...]
 }
```

All fields that are indicated inside a bracket ([.md](.md)) are optional and are not always defined. Most of these fields have a direct relationship to the [l2t\_csv](l2t_csv.md) output.

The time value inside the timestamp object is another hash that can store all the timestamps that might be within each timestamp object. The index value is simply an integer that is incremented by one for each timestamp associated to the event. Most of the fields are common among all timestamps in each entry, thus they are not defined inside each time event. The fields that do change are the '_value_', '_type_', and '_legacy_'. The meaning of these fields is the following:
  * **value**: The epoch value of the timestamp (normalized to UTC).
  * **type**: The description of the type of timestamp, eg. "Last Written", "Last Visited", etc.
  * **legacy**: An integer describing the legacy value or the MACB value of the timestamp if it needs to be represented that way. The field is set up as a binary value where BCAM is directly mapped to a binary value.
| **Legacy** | **B** | **C** | **A** | **M** | **Value** |
|:-----------|:------|:------|:------|:------|:----------|
| MACB       | 1     | 1     | 1     | 1     | 15        |
| M...       | 0     | 0     | 0     | 1     | 1         |
| .AC.       | 0     | 1     | 1     | 0     | 6         |
