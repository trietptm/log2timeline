#!/usr/bin/perl
#########################################################################################
#                       Win
#########################################################################################
# This is a small library that is a part of the tool log2timeline. It's purpose is to
# assist with various common functions that are used by more than one module.
#
# This library is intended to provide information about Windows systems, such as
# a list of know GUID's or other lookup tables that need to be performed by more
# than one input module that is used to query information from a Windows sytem.
#
# For a list of "known" GUID's this site was used as a reference
#	http://msdn.microsoft.com/en-us/library/dd378457%28VS.85%29.aspx
#
# Author: Kristinn Gudjonsson
# Date : 13/10/09
#
# Copyright 2009 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::Win;

use strict;
use Exporter qw(import);

# transform gathered from these sources:
# http://www.pcreview.co.uk/forums/return-system-timezone-abbreviation-format-e-cst-t2788903.html
# http://msdn.microsoft.com/en-us/library/ms912391(v=winembedded.11).aspx
my %known_timezone_transforms = (
    'India Standard Time'           => 'Asia/Kolkata',
    'Eastern Standard Time'         => 'EST5EDT',
    'Eastern Daylight Time'         => 'EST5EDT',
    'Mountain Standard Time'        => 'MST7MDT',
    'Mountain Daylight Time'        => 'MST7MDT',
    'Pacific Standard Time'         => 'PST7PDT',
    'Pacific Daylight Time'         => 'PST7PDT',
    'Central Standard Time'         => 'CST6CDT',
    'Central Daylight Time'         => 'CST6CDT',
    'Samoa Standard Time'           => 'US/Samoa',
    'Hawaiian Standard Time'        => 'US/Hawaii',
    'Alaskan Standard Time'         => 'US/Alaska',
    'Pacific Standard Time'         => 'PST8PDT',
    'Mexico Standard Time 2'        => 'MST7MDT',
    'US Mountain Standard Time'     => 'MST7MDT',
    'Canada Central Standard Time'  => 'CST6CDT',
    'Mexico Standard Time'          => 'CST6CDT',
    'Central Standard Time'         => 'CST6CDT',
    'Central America Standard Time' => 'CST6CDT',
    'US Eastern Standard Time'      => 'EST5EDT',
    'SA Pacific Standard Time'      => 'EST5EDT',
    'Malay Peninsula Standard Time' => 'Asia/Kuching'
    '@tzres.dll,-365'               => 'Egypt',
    'Pacific SA Standard Time'      => 'Canada/Atlantic',
    'Atlantic Standard Time'        => 'Canada/Atlantic',
    'SA Western Standard Time'      => 'Canada/Atlantic',
    'Newfoundland Standard Time'    => 'Canada/Newfoundland',
    #	'Greenland Standard Time' => 'BBA',
    #	'SA Eastern Standard Time' => 'BBA',
    #	'E. South America Standard Time' => 'BBA',
    #	'Mid-Atlantic Standard Time' => 'MAT',
    'Azores Standard Time' => 'Atlantic/Azores',
    'Cape Verde Standard Time' => 'Atlantic/Azores',
    'GMT Standard Time'       => 'GMT',
    'Greenwich Standard Time' => 'GMT',
    'W. Central Africa Standard Time' => 'Europe/Belgrade',
    'W. Europe Standard Time' => 'Europe/Belgrade',
    'Central Europe Standard Time' => 'Europe/Belgrade',
    'Romance Standard Time' => 'Europe/Belgrade',
    'Central European Standard Time' => 'Europe/Belgrade',
    #	'GTB Standard Time' => 'AIM',
    'E. Europe Standard Time' => 'Egypt',
    'South Africa Standard Time' => 'Egypt',
    'Israel Standard Time' => 'Egypt',
    'Egypt Standard Time' => 'Egypt',
    #	'FLE Standard Time' => 'HRI',
    #	'Arabic Standard Time' => 'BKR',
    #	'Arab Standard Time' => 'BKR',
    #	'Russian Standard Time' => 'MSV',
    #	'E. Africa Standard Time' => 'BKR',
    #	'Iran Standard Time' => 'THE',
    #	'Arabian Standard Time' => 'ABT',
    #	'Caucasus Standard Time' => 'ABT',
    #	'Afghanistan Standard Time' => 'KAB',
    #	'Ekaterinburg Standard Time' => 'EIK',
    #	'West Asia Standard Time' => 'EIK',
    #	'Nepal Standard Time' => 'NPT',
    #	'N. Central Asia Standard Time' => 'ADC',
    #	'Central Asia Standard Time' => 'ADC',
    #	'Sri Lanka Standard Time' => 'ADC',
    #	'Myanmar Standard Time' => 'MMT',
    #	'SE Asia Standard Time' => 'BHJ',
    #	'North Asia Standard Time' => 'BHJ',
    'North Asia East Standard Time' => 'Asia/Bangkok',
    'Singapore Standard Time' => 'Asia/Bangkok',
    'China Standard Time' => 'Asia/Bangkok',
    'W. Australia Standard Time' => 'Asia/Bangkok',
    'Taipei Standard Time' => 'Asia/Bangkok',
    'Tokyo Standard Time' => 'Asia/Tokyo',
    'Korea Standard Time' => 'Asia/Seoul',
    #	'Yakutsk Standard Time' => 'SYA',
    #	'Cen. Australia Standard Time' => 'ADA',
    #	'AUS Central Standard Time' => 'ADA',
    #	'E. Australia Standard Time' => 'BGP',
    #	'West Pacific Standard Time' => 'BGP',
    #	'AUS Eastern Standard Time' => 'CMS',
    #	'Tasmania Standard Time' => 'HVL',
    #	'Vladivostok Standard Time' => 'HVL',
    #	'Central Pacific Standard Time' => 'MSN',
    #	'New Zealand Standard Time' => 'AWE',
    #	'Fiji Standard Time' => 'FKM',
    #	'Tonga Standard Time' => 'TOT',
                                );

# A list of known guids in Windows Vista and newer Windows operating systems
my %known_guids = (
    '{de61d971-5ebc-4f02-a3a9-6c82895e5c04}' => { 'name' => 'Get Programs', 'path' => 'VIRTUAL' },
    '{724EF170-A42D-4FEF-9F26-B60E846FBA4F}' => {
                    'name' => 'Administrative Tools',
                    'path' => '%APPDATA%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'
    },
    '{a305ce99-f527-492b-8b1a-7e76fa98d6e4}' =>
      { 'name' => 'Installed Updates', 'path' => 'VIRTUAL' },
    '{9E52AB10-F80D-49DF-ACB8-4330F5687855}' =>
      { 'name' => 'Temporary Burn Folder', 'path' => '%LOCALAPPDATA%\Microsoft\Windows\Burn\Burn' },
    '{df7266ac-9274-4867-8d55-3bd661de872d}' =>
      { 'name' => 'Programs and Features', 'path' => 'VIRTUAL' },
    '{D0384E7D-BAC3-4797-8F14-CBA229B392B5}' => {
            'name' => 'Administrative Tools',
            'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Administrative Tools'
    },
    '{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}' =>
      { 'name' => 'OEM Links', 'path' => '%ALLUSERSPROFILE%\OEM Links' },
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' =>
      { 'name' => 'Programs', 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs' },
    '{A4115719-D62E-491D-AA7C-E74B8BE3B067}' =>
      { 'name' => 'Start Menu', 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu' },
    '{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}' => {
                         'name' => 'Startup',
                         'path' => '	%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\StartU'
    },
    '{B94237E7-57AC-4347-9151-B08C6C32D1F7}' =>
      { 'name' => 'Templates', 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\Templates' },
    '{0AC0837C-BBF8-452A-850D-79D08E667CA7}' => { 'name' => 'Computer',  'path' => 'VIRTUAL' },
    '{4bfefb45-347d-4006-a5be-ac0cb0567192}' => { 'name' => 'Conflicts', 'path' => 'VIRTUAL' },
    '{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}' =>
      { 'name' => 'Network Connections', 'path' => 'VIRTUAL' },
    '{56784854-C6CB-462b-8169-88E350ACB882}' =>
      { 'name' => 'Contacts', 'path' => '%USERPROFILE%\Contacts' },
    '{82A74AEB-AEB4-465C-A014-D097EE346D63}' => { 'name' => 'Control Panel', 'path' => 'VIRTUAL' },
    '{2B0F765D-C0E9-4171-908E-08A611B84FF6}' =>
      { 'name' => 'Cookies', 'path' => '%APPDATA%\Microsoft\Windows\Cookies' },
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' =>
      { 'name' => 'Desktop', 'path' => '%USERPROFILE%\Desktop' },
    '{5CE4A5E9-E4EB-479D-B89F-130C02886155}' => {
                                 'name' => 'DeviceMetadataStore',
                                 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\DeviceMetadataStore'
    },
    '{7B0DB17D-9CD2-4A93-9733-46CC89022E7C}' => {
                              'name' => 'Documents',
                              'path' => '%APPDATA%\Microsoft\Windows\Libraries\Documents.library-ms'
    },
    '{374DE290-123F-4565-9164-39C4925E467B}' =>
      { 'name' => 'Downloads', 'path' => '%USERPROFILE%\Downloads' },
    '{1777F761-68AD-4D8A-87BD-30B759FA33DD}' =>
      { 'name' => 'Favorites', 'path' => '%USERPROFILE%\Favorites' },
    '{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}' => { 'name' => 'Fonts', 'path' => '%windir%\Fonts' },
    '{CAC52C1A-B53D-4edc-92D7-6B2E8AC19434}' => { 'name' => 'Games', 'path' => 'VIRTUAL' },
    '{054FAE61-4DD8-4787-80B6-090220C4B700}' =>
      { 'name' => 'GameExplorer', 'path' => '%LOCALAPPDATA%\Microsoft\Windows\GameExplorer' },
    '{D9DC8A3B-B784-432E-A781-5A1130A75963}' =>
      { 'name' => 'History', 'path' => '%LOCALAPPDATA%\Microsoft\Windows\History' },
    '{52528A6B-B9E3-4ADD-B60D-588C2DBA842D}' => { 'name' => 'Homegroup', 'path' => 'VIRTUAL' },
    '{BCB5256F-79F6-4CEE-B725-DC34E402FD46}' => {
             'name' => 'ImplicitAppShortcuts',
             'path' =>
               '%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts'
    },
    '{352481E8-33BE-4251-BA85-6007CAEDCF9D}' => {
                               'name' => 'Temporary Internet Files',
                               'path' => '%LOCALAPPDATA%\Microsoft\Windows\Temporary Internet Files'
    },
    '{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}' =>
      { 'name' => 'Internet Explorer', 'path' => 'VIRTUAL' },
    '{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}' =>
      { 'name' => 'Libraries', 'path' => '%APPDATA%\Microsoft\Windows\Libraries' },
    '{bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968}' =>
      { 'name' => 'Links', 'path' => '%USERPROFILE%\Links' },
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' =>
      { 'name' => 'Local', 'path' => '%LOCALAPPDATA% (%USERPROFILE%\AppData\Local)' },
    '{A520A1A4-1780-4FF6-BD18-167343C5AF16}' =>
      { 'name' => 'LocalLow', 'path' => '%USERPROFILE%\AppData\LocalLow' },
    '{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}' =>
      { 'name' => 'None', 'path' => '%windir%\resources\0409 (code page)' },
    '{4BD8D571-6D19-48D3-BE97-422220080E43}' =>
      { 'name' => 'Music', 'path' => '%USERPROFILE%\Music' },
    '{2112AB0A-C86A-4FFE-A368-0DE96E47012E}' =>
      { 'name' => 'Music', 'path' => '%APPDATA%\Microsoft\Windows\Libraries\Music.library-ms' },
    '{C5ABBF53-E17F-4121-8900-86626FC2C973}' =>
      { 'name' => 'Network Shortcuts', 'path' => '%APPDATA%\Microsoft\Windows\Network Shortcuts' },
    '{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}' => { 'name' => 'Network', 'path' => 'VIRTUAL' },
    '{2C36C0AA-5812-4b87-BFD0-4CD0DFB19B39}' => {
                          'name' => 'Original Images',
                          'path' => '%LOCALAPPDATA%\Microsoft\Windows Photo Gallery\Original Images'
    },
    '{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}' =>
      { 'name' => 'Slide Shows', 'path' => '%USERPROFILE%\Pictures\Slide Shows' },
    '{A990AE9F-A03B-4E80-94BC-9912D7504104}' => {
                               'name' => 'Pictures',
                               'path' => '%APPDATA%\Microsoft\Windows\Libraries\Pictures.library-ms'
    },
    '{33E28130-4E1E-4676-835A-98395C3BC3BB}' =>
      { 'name' => 'Pictures', 'path' => '%USERPROFILE%\Pictures' },
    '{DE92C1C7-837F-4F69-A3BB-86E631204A23}' =>
      { 'name' => 'Playlists', 'path' => '%USERPROFILE%\Music\Playlists' },
    '{76FC4E2D-D6AD-4519-A663-37BD56068185}' => { 'name' => 'Printers', 'path' => 'VIRTUAL' },
    '{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}' =>
      { 'name' => 'Printer Shortcuts', 'path' => '%APPDATA%\Microsoft\Windows\Printer Shortcuts' },
    '{5E6C858F-0E22-4760-9AFE-EA3317B67173}' => {
                                          'name' => 'The user\'s username (%USERNAME%)',
                                          'path' => '%USERPROFILE% (%SystemDrive%\Users\%USERNAME%)'
    },
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' => {
                            'name' => 'ProgramData',
                            'path' => '%ALLUSERSPROFILE% (%ProgramData%, %SystemDrive%\ProgramData)'
    },
    '{905e63b6-c1bf-494e-b29c-65b732d3d21a}' =>
      { 'name' => 'Program Files', 'path' => '%ProgramFiles% (%SystemDrive%\Program Files)' },
    '{6D809377-6AF0-444b-8957-A3773F02200E}' =>
      { 'name' => 'Program Files', 'path' => '[X64] %ProgramFiles% (%SystemDrive%\Program Files)' },
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' =>
      { 'name' => 'Program Files', 'path' => '[X86] %ProgramFiles% (%SystemDrive%\Program Files)' },
    '{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}' =>
      { 'name' => 'Common Files', 'path' => '%ProgramFiles%\Common Files' },
    '{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}' =>
      { 'name' => 'Common Files', 'path' => '[X64] %ProgramFiles%\Common Files' },
    '{DE974D24-D9C6-4D3E-BF91-F4455120B917}' =>
      { 'name' => 'Common Files', 'path' => '[X86] %ProgramFiles%\Common Files' },
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' =>
      { 'name' => 'Programs', 'path' => '%APPDATA%\Microsoft\Windows\Start Menu\Programs' },
    '{DFDF76A2-C82A-4D63-906A-5644AC457385}' =>
      { 'name' => 'Public', 'path' => '%PUBLIC% (%SystemDrive%\Users\Public)' },
    '{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}' =>
      { 'name' => 'Public Desktop', 'path' => '%PUBLIC%\Desktop' },
    '{ED4824AF-DCE4-45A8-81E2-FC7965083634}' =>
      { 'name' => 'Public Documents', 'path' => '%PUBLIC%\Documents' },
    '{3D644C9B-1FB8-4f30-9B45-F670235F79C0}' =>
      { 'name' => 'Public Downloads', 'path' => '%PUBLIC%\Downloads' },
    '{DEBF2536-E1A8-4c59-B6A2-414586476AEA}' =>
      { 'name' => 'GameExplorer', 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\GameExplorer' },
    '{48DAF80B-E6CF-4F4E-B800-0E69D84EE384}' =>
      { 'name' => 'Libraries', 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\Libraries' },
    '{3214FAB5-9757-4298-BB61-92A9DEAA44FF}' =>
      { 'name' => 'Public Music', 'path' => '%PUBLIC%\Music' },
    '{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}' =>
      { 'name' => 'Public Pictures', 'path' => '%PUBLIC%\Pictures' },
    '{E555AB60-153B-4D17-9F04-A5FE99FC15EC}' =>
      { 'name' => 'Ringtones', 'path' => '%ALLUSERSPROFILE%\Microsoft\Windows\Ringtones' },
    '{2400183A-6185-49FB-A2D8-4A392A602BA3}' =>
      { 'name' => 'Public Videos', 'path' => '%PUBLIC%\Videos' },
    '{52a4f021-7b75-48a9-9f6b-4b87a210bc8f}' =>
      { 'name' => 'Quick Launch', 'path' => '%APPDATA%\Microsoft\Internet Explorer\Quick Launch' },
    '{AE50C081-EBD2-438A-8655-8A092E34987A}' =>
      { 'name' => 'Recent Items', 'path' => '%APPDATA%\Microsoft\Windows\Recent' },
    '{1A6FDBA2-F42D-4358-A798-B74D745926C5}' =>
      { 'name' => 'Recorded TV', 'path' => '%PUBLIC%\RecordedTV.library-ms' },
    '{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}' => { 'name' => 'Recycle Bin', 'path' => 'VIRTUAL' },
    '{8AD10C31-2ADB-4296-A8F7-E4701232C972}' =>
      { 'name' => 'Resources', 'path' => '%windir%\Resources' },
    '{C870044B-F49E-4126-A9C3-B52A1FF411E8}' =>
      { 'name' => 'Ringtones', 'path' => '%LOCALAPPDATA%\Microsoft\Windows\Ringtones' },
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' =>
      { 'name' => 'Roaming', 'path' => '%APPDATA% (%USERPROFILE%\AppData\Roaming)' },
    '{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}' =>
      { 'name' => 'Sample Music', 'path' => '%PUBLIC%\Music\Sample Music' },
    '{C4900540-2379-4C75-844B-64E6FAF8716B}' =>
      { 'name' => 'Sample Pictures', 'path' => '	%PUBLIC%\Pictures\Sample Pictures' },
    '{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}' =>
      { 'name' => 'Sample Playlists', 'path' => '%PUBLIC%\Music\Sample Playlists' },
    '{859EAD94-2E85-48AD-A71A-0969CB56A6CD}' =>
      { 'name' => 'Sample Videos', 'path' => '%PUBLIC%\Videos\Sample Videos' },
    '{4C5C32FF-BB9D-43b0-B5B4-2D72E54EAAA4}' =>
      { 'name' => 'Saved Games', 'path' => '%USERPROFILE%\Saved Games' },
    '{7d1d3a04-debb-4115-95cf-2f29da2920da}' =>
      { 'name' => 'Searches', 'path' => '	%USERPROFILE%\Searches' },
    '{ee32e446-31ca-4aba-814f-a5ebd2fd6d5e}' => { 'name' => 'Offline Files', 'path' => 'VIRTUAL' },
    '{98ec0e18-2098-4d44-8644-66979315a281}' =>
      { 'name' => 'Microsoft Office Outlook', 'path' => 'VIRTUAL' },
    '{190337d1-b8ca-4121-a639-6d472d16972a}' => { 'name' => 'Search Results', 'path' => 'VIRTUAL' },
    '{8983036C-27C0-404B-8F08-102D10DCFD74}' =>
      { 'name' => 'SendTo', 'path' => '%APPDATA%\Microsoft\Windows\SendTo' },
    '{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}' =>
      { 'name' => 'Gadgets', 'path' => '%ProgramFiles%\Windows Sidebar\Gadgets' },
    '{A75D362E-50FC-4fb7-AC2C-A8BEAA314493}' =>
      { 'name' => 'Gadgets', 'path' => '%LOCALAPPDATA%\Microsoft\Windows Sidebar\Gadgets' },
    '{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}' =>
      { 'name' => 'Start Menu', 'path' => '%APPDATA%\Microsoft\Windows\Start Menu' },
    '{B97D20BB-F46A-4C97-BA10-5E3608430854}' =>
      { 'name' => 'Startup', 'path' => '%APPDATA%\Microsoft\Windows\Start Menu\Programs\StartUp' },
    '{43668BF8-C14E-49B2-97C9-747784D784B7}' => { 'name' => 'Sync Center',  'path' => 'VIRTUAL' },
    '{289a9a43-be44-4057-a41b-587a76d7e7f9}' => { 'name' => 'Sync Results', 'path' => 'VIRTUAL' },
    '{0F214138-B1D3-4a90-BBA9-27CBC0C5389A}' => { 'name' => 'Sync Setup',   'path' => 'VIRTUAL' },
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' =>
      { 'name' => 'System32', 'path' => '%windir%\system32' },
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' =>
      { 'name' => '[X86] System32', 'path' => '%windir%\system32' },
    '{A63293E8-664E-48DB-A079-DF759E0509F7}' =>
      { 'name' => 'Templates', 'path' => '%APPDATA%\Microsoft\Windows\Templates' },
    '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' => {
                          'name' => 'User Pinned',
                          'path' => '%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned'
    },
    '{0762D272-C50A-4BB0-A382-697DCD729B80}' =>
      { 'name' => 'Users', 'path' => '%SystemDrive%\Users' },
    '{5CD7AEE2-2219-4A67-B85D-6C9CE15660CB}' =>
      { 'name' => 'Programs', 'path' => '%LOCALAPPDATA%\Programs' },
    '{BCBD3057-CA5C-4622-B42D-BC56DB0AE516}' =>
      { 'name' => 'Programs', 'path' => '%LOCALAPPDATA%\Programs\Common' },
    '{f3ce0f7c-4901-4acc-8648-d5d44b04ef8f}' => {
                     'name' => 'The user\'s full name -  entered when the user account was created',
                     'path' => 'VIRTUAL'
    },
    '{A302545D-DEFF-464b-ABE8-61C8648D939B}' => { 'name' => 'Libraries', 'path' => 'VIRTUAL' },
    '{18989B1D-99B5-455B-841C-AB7C74E4DDFC}' =>
      { 'name' => 'Videos', 'path' => '%USERPROFILE%\Videos' },
    '{491E922F-5643-4AF4-A7EB-4E7A138D8174}' =>
      { 'name' => 'Videos', 'path' => '%APPDATA%\Microsoft\Windows\Libraries\Videos.library-ms' },
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' => { 'name' => 'Windows', 'path' => '%windir%' },

    # GUID gathered elsewere
    '{2559A1F5-21D7-11D4-BDAF-00C04F60B9F0}' =>
      { 'name' => 'E-mail', 'path' => '%SystemRoot%\system32\shdocvw.dll' },
    '{208D2C60-3AEA-1069-A2D7-08002B30309D}' =>
      { 'name' => 'My Network Places', 'path' => 'VIRTUAL' },
    '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' => { 'name' => 'My Computer',  'path' => 'VIRTUAL' },
    '{450D8FBA-AD25-11D0-98A8-0800361B1103}' => { 'name' => 'My Documents', 'path' => 'VIRTUAL' },
    '{645FF040-5081-101B-9F08-00AA002F954E}' => { 'name' => 'Recycle bin',  'path' => 'VIRTUAL' },

    # GUID from http://forum.securitycadets.com/index.php?showtopic=12840
    '{00000409-78E1-11D2-B60F-006097C998E7}' =>
      { name => '[should be] Microsoft Office 2000 SR-1 Premium', path => 'NA' },
    '{025C3792-E9C6-432A-92C1-661F99D021CA}' =>
      { name => '[should be] Ulead Photo Explorer 8.5 SE', path => 'NA' },
    '{04410044-9149-45C6-A806-F2BF9CFCE762}' =>
      { name => '[should be] Microsoft Encarta Encyclopedia Standard 2004', path => 'NA' },
    '{09DA4F91-2A09-4232-AB8C-6BC740096DE3}' => { name => 'Sonic Update Manager', path => 'NA' },
    '{11F1920A-56A2-4642-B6E0-3B31A12C9288}' => { name => 'Dell Solution Center', path => 'NA' },
    '{1206EF92-2E83-4859-ACCB-2048C3CB7DA6}' => { name => 'Sonic DLA, path' => 'NA' },
    '{12BDDF23-B1DB-49C8-92D3-3E6841CCED61}' =>
      { name => '[should be] Microsoft Streets and Trips 2002', path => 'NA' },
    '{1D643CD7-4DD6-11D7-A4E0-000874180BB3}' => { name => 'Microsoft Money 2004', path => 'NA' },
    '{1F90C982-33C6-11D3-A3E0-00C04F7989D8}' =>
      { name => 'Microsoft Home Publishing Express 2000', path => 'NA' },
    '{206A595B-6ED6-4547-9293-C448139826EC}' => { name => 'CallAtlanta, path' => 'NA' },
    '{25569723-DC5A-4467-A639-79535BF01B71}' =>
      { name => '[should be] Adobe Help Center 2.1', path => 'NA' },
    '{2637C347-9DAD-11D6-9EA2-00055D0CA761}' => { name => 'Dell Media Experience', path => 'NA' },
    '{26A24AE4-039D-4CA4-87B4-2F83216010FF}' =>
      { name => '[should be] Java (TM) 6 Update 13', path => 'NA' },
    '{31E1050B-F69F-4A16-8F5A-E44D31901250}' =>
      { name => '[should be] Ulead DVD DiskRecorder 2.1.1', path => 'NA' },
    '{3248F0A8-6813-11D6-A77B-00B0D0160020}' =>
      { name => '[should be] Java (TM) 6 Update 2', path => 'NA' },
    '{3248F0A8-6813-11D6-A77B-00B0D0160030}' =>
      { name => '[should be] Java (TM) 6 Update 3', path => 'NA' },
    '{3248F0A8-6813-11D6-A77B-00B0D0160070}' =>
      { name => '[should be] Java (TM) 6 Update 7', path => 'NA' },
    '{350C97B0-3D7C-4EE8-BAA9-00BCB3D54227}' => { name => 'WebFldrs XP', path => 'NA' },
    '{35BDEFF1-A610-4956-A00D-15453C116395}' =>
      { name => 'Internet Explorer Default Page', path => 'NA' },
    '{3868A8EE-5051-4DB0-8DF6-4F4B8A98D083}' => { name => 'QuickTime', path => 'NA' },
    '{388C130B-0079-46B4-A0D5-DC2DD7A89A7B}' =>
      { name => 'Citrix XenApp Plugin for Hosted Apps', path => 'NA' },
    '{40BF1E83-20EB-11D8-97C5-0009C5020658}' =>
      { name => '[should be] Power2Go 4.0', path => 'NA' },
    '{433DDA5A-8016-44B2-AC00-89BE268C6EA6}' =>
      { name => '[should be] eWebEditPro with WebImageFX Client', path => 'NA' },
    '{43DCF766-6838-4F9A-8C91-D92DA586DFA7}' =>
      { name => 'Microsoft Windows Journal Viewer', path => 'NA' },
    '{43FCA273-9534-40DB-B7C5-D7758875616A}' => { name => 'Dell Support', path => 'NA' },
    '{448AB2CB-C94A-47DE-80B8-9D7824DEFA57}' =>
      { name => '[should be] Ulead DVD MovieFactory 4 Suite Deluxe', path => 'NA' },
    '{45EBDA59-D33B-433A-956E-B2F236468B56}' =>
      { name => '[should be] MUSICMATCH Jukebox', path => 'NA' },
    '{489B7615-D69F-4260-B884-8D82D706B524}' =>
      { name => '[should be] Norton Spyware Scan', path => 'NA' },
    '{4A7FDA4D-F4D7-4A49-934A-066D59A43C7E}' =>
      { name => '[should be] SmartSound Quicktracks Plugin', path => 'NA' },
    '{4B9F45E8-E3CE-40B4-9463-80A9B3481DEF}' =>
      { name => '[should be] Banctec Service Agreement', path => 'NA' },
    '{4E839090-3B68-436A-B3CF-A2A08C38DD26}' =>
      { name => '[should be] TiVo Desktop', path => 'NA' },
    '{4FBF4810-CC11-4985-BD7B-4E80536075FD}' =>
      { name => '[should be] MPIO Plugins Pack', path => 'NA' },
    '{541DEAC0-5F3D-45E6-B7CB-94ECF3B96748}' =>
      { name => '[should be] Skype web features', path => 'NA' },
    '{54F90B55-BEB3-4F0D-8802-228822FA5921}' =>
      { name => '[should be] WordPerfect Office 11', path => 'NA' },
    '{6811CAA0-BF12-11D4-9EA1-0050BAE317E1}' => { name => 'PowerDVD', path => 'NA' },
    '{68D60342-7686-45C9-B8EB-40EF843D0460}' =>
      { name => '[should be] Dell Networking Guide', path => 'NA' },
    '{6ECB39BD-73C2-44DD-B1A0-898207C58D8B}' =>
      { name => '[should be] HP Photo and Imaging 2.0 - All-in-One Drivers', path => 'NA' },
    '{7299052b-02a4-4627-81f2-1818da5d550d}' =>
      { name => '[should be] Microsoft Visual C++ 2005 Redistributable', path => 'NA' },
    '{7F142D56-3326-11D5-B229-002078017FBF}' =>
      { name => '[should be] Modem Helper', path => 'NA' },
    '{81A34902-9D0B-4920-A25C-4CDC5D14B328}' =>
      { name => '[should be] Jasc Paint Shop Pro 8 Dell Edition', path => 'NA' },
    '{872653C6-5DDC-488B-B7C2-CF9E4D9335E5}' => { name => 'iTunes', path => 'NA' },
    '{88F3DD4D-C46C-4312-84DA-603087D3F86B}' =>
      { name => '[should be] hp officejet 4100 series', path => 'NA' },
    '{89EE857B-8970-4F9F-AB58-A1C873AC72B3}' =>
      { name => '[should be] Broadcom Management Programs', path => 'NA' },
    '{8A708DD8-A5E6-11D4-A706-000629E95E20}' =>
      { name => '[should be] Intel Extreme Graphics Driver', path => 'NA' },
    '{8C64E145-54BA-11D6-91B1-00500462BE80}' =>
      { name => '[should be] Microsoft Money 2004 System Pack', path => 'NA' },
    '{8EAB2384-C794-40ED-A9DD-3270A0D2BB76}' =>
      { name => '[should be] Ulead VideoStudio 9.0 SE DVD', path => 'NA' },
    '{90120000-0020-0409-0000-0000000FF1CE}' =>
      { name => '[should be] Compatibility Pack for the 2007 Office system', path => 'NA' },
    '{90D55A3F-1D99-4C94-A77E-46DC14F0BF08}' =>
      { name => 'Help and Support Customization', path => 'NA' },
    '{9541FED0-327F-4DF0-8B96-EF57EF622F19}' =>
      { name => '[should be] Sonic RecordNow!', path => 'NA' },
    '{96E16100-A77F-4B31-B9AD-FFBA040EE1BD}' =>
      { name => '[should be] Sound Blaster Live!', path => 'NA' },
    '{9867A917-5D17-40DE-83BA-BEA5293194B1}' =>
      { name => '[should be] HP Photo and Imaging 2.0 - All-in-One, path' => 'NA' },
    '{A14F19F4-2E19-4CA5-83AB-FC9EE3FEA1E0}' => { name => 'NovaBACKUP, path' => 'NA' },
    '{A5FCC3DE-56BD-48b2-8054-4BBE70BE186B}' =>
      { name => '[should be] eFax Messenger Plus 3.3', path => 'NA' },
    '{A7B609FB-83D8-4FC3-8477-1BC65ECFE85B}' =>
      { name => '[should be] Adobe Photoshop Elements 5.0', path => 'NA' },
    '{AC76BA86-7AD7-1033-7B44-A81200000003}' =>
      { name => '[should be] Adobe Reader 8.1.2', path => 'NA' },
    '{AD8E6D29-95EC-494E-8AF5-566E784819A6}' =>
      { name => '[should be] Ulead Data-Add 2.0', path => 'NA' },
    '{B376402D-58EA-45EA-BD50-DD924EB67A70}' => { name => 'HP Memories Disc', path => 'NA' },
    '{B4092C6D-E886-4CB2-BA68-FE5A88D31DE6}' =>
      { name => 'Spybot - Search & Destroy', path => 'NA' },
    '{B4FEA924-630D-11D4-B78E-005004566E4D}' =>
      { name => 'ViewSonic Monitor Drivers', path => 'NA' },
    '{B7A0CE06-068E-11D6-97FD-0050BACBF861}' => { name => 'PowerProducer',   path => 'NA' },
    '{C559CCD6-E2B8-4C7B-9791-AB68F382F9C2}' => { name => 'DirectShow Dump', path => 'NA' },
    '{C82E1703-ACBB-4015-856B-A8A0E5BAC661}' =>
      { name => '[should be] Ulead CD & DVD PictureShow 3 SE', path => 'NA' },
    '{CB2F7EDD-9D1F-43C1-90FC-4F52EAE172A1}' =>
      { name => '[should be] Microsoft .NET Framework 1.1', path => 'NA' },
    '{CDDCBBF1-2703-46BC-938B-BCC81A1EEAAA}' =>
      { name => 'SUPERAntiSpyware Free Edition', path => 'NA' },
    '{D103C4BA-F905-437A-8049-DB24763BBE36}' =>
      { name => '[should be] Skype (TM) 4.1', path => 'NA' },
    '{E3436EE2-D5CB-4249-840B-3A0140CC34C3}' => { name => 'Classic PhoneTools', path => 'NA' },
    '{E38C00D0-A68B-4318-A8A6-F7D4B5B1DF0E}' =>
      { name => '[should be] Windows Media Encoder 9 Series', path => 'NA' },
    '{E5C13A44-7C32-4CBB-B318-518B54F834C5}' =>
      { name => '[should be] Ulead DVD Player 2.0', path => 'NA' },
    '{EDE721EC-870A-11D8-9D75-000129760D75}' => { name => 'PowerDirector Express', path => 'NA' },
    '{F3BCD513-E086-4058-B93E-173780E583A2}' =>
      { name => '[should be] Microsoft MapPoint 2002 North America', path => 'NA' },
    '{FC4ED75D-916C-4A8C-BB67-3C6F6E06D62B}' =>
      { name => 'Banctec Service Agreement', path => 'NA' },
    '{FCE65C4E-B0E8-4FBD-AD16-EDCBE6CD591F}' =>
      { name => 'HighMAT Extension to Microsoft Windows XP CD Writing Wizard', path => 'NA' },

# taken from here: http://www.mydigitallife.info/2010/01/14/list-of-canonical-names-and-guid-for-control-panel-items-clsid-to-make-god-modes/
    "{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" => {
                                     "name" => "Microsoft.ActionCenter (Windows 7 and later only) ",
                                     "path" => "Control Panel: Action Center "
    },
    "{D20EA4E1-3957-11d2-A40B-0C5020524153}" => {
                                                  "name" => "Microsoft.AdministrativeTools ",
                                                  "path" => "Control Panel: Administrative Tools "
                                                },
    "{9C60DE1E-E5FC-40f4-A487-460851A8D915}" =>
      { "name" => "Microsoft.AutoPlay ", "path" => "Control Panel: AutoPlay " },
    "{0142e4d0-fb7a-11dc-ba4a-000ffe7ab428}" => {
                                 "name" => "Microsoft.BiometricDevices (Windows 7 and later only) ",
                                 "path" => "Control Panel: Biometric Devices "
    },
    "{D9EF8727-CAC2-4e60-809E-86F80A666C91}" => {
                                              "name" => "Microsoft.BitLockerDriveEncryption ",
                                              "path" => "Control Panel: BitLocker Drive Encryption "
    },
    "{B2C761C6-29BC-4f19-9251-E6195265BAF1}" =>
      { "name" => "Microsoft.ColorManagement ", "path" => "Control Panel: Color Management " },
    "{1206F5F1-0569-412C-8FEC-3204630DFB70}" => {
                                "name" => "Microsoft.CredentialManager (Windows 7 and later only) ",
                                "path" => "Control Panel: Credential Manager "
    },
    "{E2E7934B-DCE5-43C4-9576-7FE4F75E7480}" =>
      { "name" => "Microsoft.DateAndTime ", "path" => "Control Panel: Date and Time " },
    "{00C6D95F-329C-409a-81D7-C46C66EA7F33}" => {
                                  "name" => "Microsoft.DefaultLocation (Windows 7 and later only) ",
                                  "path" => "Control Panel: Default Location "
    },
    "{17cd9488-1228-4b2f-88ce-4298e93e0966}" =>
      { "name" => "Microsoft.DefaultPrograms ", "path" => "Control Panel: Default Programs " },
    "{74246bfc-4c96-11d0-abef-0020af6b0b7a}" =>
      { "name" => "Microsoft.DeviceManager ", "path" => "Control Panel: Device Manager " },
    "{A8A91A66-3A7D-4424-8D24-04E180695C7A}" => {
                               "name" => "Microsoft.DevicesAndPrinters (Windows 7 and later only) ",
                               "path" => "Control Panel: Devices and Printers "
    },
    "{C555438B-3C23-4769-A71F-B6D3D9B6053A}" => {
                                          "name" => "Microsoft.Display (Windows 7 and later only) ",
                                          "path" => "Control Panel: Display "
    },
    "{D555645E-D4F8-4c29-A827-D93C859C4F2A}" => {
                                                  "name" => "Microsoft.EaseOfAccessCenter ",
                                                  "path" => "Control Panel: Ease of Access Center "
                                                },
    "{6DFD7C5C-2451-11d3-A299-00C04F8EF6AF}" =>
      { "name" => "Microsoft.FolderOptions ", "path" => "Control Panel: Folder Options " },
    "{93412589-74D4-4E4E-AD0E-E0CB621440FD}" =>
      { "name" => "Microsoft.Fonts ", "path" => "Control Panel: Fonts " },
    "{259EF4B1-E6C9-4176-B574-481532C9BCE8}" =>
      { "name" => "Microsoft.GameControllers ", "path" => "Control Panel: Game Controllers " },
    "{15eae92e-f17a-4431-9f28-805e482dafd4}" =>
      { "name" => "Microsoft.GetPrograms ", "path" => "Control Panel: Get Programs " },
    "{67CA7650-96E6-4FDD-BB43-A8E774F73A57}" => {
                                        "name" => "Microsoft.HomeGroup (Windows 7 and later only) ",
                                        "path" => "Control Panel: HomeGroup "
    },
    "{87D66A43-7B11-4A28-9811-C86EE395ACF7}" =>
      { "name" => "Microsoft.IndexingOptions ", "path" => "Control Panel: Indexing Options " },
    "{A3DD4F92-658A-410F-84FD-6FBBBEF2FFFE}" =>
      { "name" => "Microsoft.InternetOptions ", "path" => "Control Panel: Internet Options " },
    "{A304259D-52B8-4526-8B1A-A1D6CECC8243}" =>
      { "name" => "Microsoft.iSCSIInitiator ", "path" => "Control Panel: iSCSI Initiator " },
    "{725BE8F7-668E-4C7B-8F90-46BDB0936430}" =>
      { "name" => "Microsoft.Keyboard ", "path" => "Control Panel: Keyboard " },
    "{E9950154-C418-419e-A90A-20C5287AE24B}" => {
                          "name" => "Microsoft.LocationAndOtherSensors (Windows 7 and later only) ",
                          "path" => "Control Panel: Location and Other Sensors "
    },
    "{6C8EEC18-8D75-41B2-A177-8831D59D2D50}" =>
      { "name" => "Microsoft.Mouse ", "path" => "Control Panel: Mouse " },
    "{8E908FC9-BECC-40f6-915B-F4CA0E70D03D}" => {
                                              "name" => "Microsoft.NetworkAndSharingCenter ",
                                              "path" => "Control Panel: Network and Sharing Center "
    },
    "{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}" => {
                            "name" => "Microsoft.NotificationAreaIcons (Windows 7 and later only) ",
                            "path" => "Control Panel: Notification Area Icons "
    },
    "{D24F75AA-4F2B-4D07-A3C4-469B3D9030C4}" =>
      { "name" => "Microsoft.OfflineFiles ", "path" => "Control Panel: Offline Files " },
    "{96AE8D84-A250-4520-95A5-A47A7E3C548B}" =>
      { "name" => "Microsoft.ParentalControls ", "path" => "Control Panel: Parental Controls " },
    "{5224F545-A443-4859-BA23-7B5A95BDC8EF}" =>
      { "name" => "Microsoft.PeopleNearMe ", "path" => "Control Panel: People Near Me " },
    "{78F3955E-3B90-4184-BD14-5397C15F1EFC}" => {
                                       "name" => "Microsoft.PerformanceInformationAndTools ",
                                       "path" => "Control Panel: Performance Information and Tools "
    },
    "{ED834ED6-4B5A-4bfe-8F11-A626DCB6A921}" =>
      { "name" => "Microsoft.Personalization ", "path" => "Control Panel: Personalization " },
    "{025A5937-A6BE-4686-A844-36FE4BEC8B6D}" =>
      { "name" => "Microsoft.PowerOptions ", "path" => "Control Panel: Power Options " },
    "{7b81be6a-ce2b-4676-a29e-eb907a5126c5}" => {
                                                  "name" => "Microsoft.ProgramsAndFeatures ",
                                                  "path" => "Control Panel: Programs and Features "
                                                },
    "{9FE63AFD-59CF-4419-9775-ABCC3849F861}" => {
                                         "name" => "Microsoft.Recovery (Windows 7 and later only) ",
                                         "path" => "Control Panel: Recovery "
    },
    "{241D7C96-F8BF-4F85-B01F-E2B043341A4B}" => {
                   "name" => "Microsoft.RemoteAppAndDesktopConnections (Windows 7 and later only) ",
                   "path" => "Control Panel: RemoteApp and Desktop Connections "
    },
    "{00f2886f-cd64-4fc9-8ec5-30ef6cdbe8c3}" => {
                                                  "name" => "Microsoft.ScannersAndCameras ",
                                                  "path" => "Control Panel: Scanners and Cameras "
                                                },
    "{9C73F5E5-7AE7-4E32-A8E8-8D23B85255BF}" =>
      { "name" => "Microsoft.SyncCenter ", "path" => "Control Panel: Sync Center " },
    "{BB06C0E4-D293-4f75-8A90-CB05B6477EEE}" =>
      { "name" => "Microsoft.System ", "path" => "Control Panel: System " },
    "{80F3F1D5-FECA-45F3-BC32-752C152E456E}" =>
      { "name" => "Microsoft.TabletPCSettings ", "path" => "Control Panel: Tablet PC Settings " },
    "{0DF44EAA-FF21-4412-828E-260A8728E7F1}" => {
                                                  "name" => "Microsoft.TaskbarAndStartMenu ",
                                                  "path" => "Control Panel: Taskbar and Start Menu "
                                                },
    "{D17D1D6D-CC3F-4815-8FE3-607E7D5D10B3}" =>
      { "name" => "Microsoft.TextToSpeech ", "path" => "Control Panel: Text to Speech " },
    "{C58C4893-3BE0-4B45-ABB5-A63E4B8C8651}" => {
                                  "name" => "Microsoft.Troubleshooting (Windows 7 and later only) ",
                                  "path" => "Control Panel: Troubleshooting "
    },
    "{60632754-c523-4b62-b45c-4172da012619}" =>
      { "name" => "Microsoft.UserAccounts ", "path" => "Control Panel: User Accounts " },
    "{BE122A0E-4503-11DA-8BDE-F66BAD1E3F3A}" => {
                                                 "name" => "Microsoft.WindowsAnytimeUpgrade ",
                                                 "path" => "Control Panel: Windows Anytime Upgrade "
                                                },
    "{78CB147A-98EA-4AA6-B0DF-C8681F69341C}" =>
      { "name" => "Microsoft.CardSpace ", "path" => "Control Panel: Windows CardSpace " },
    "{D8559EB9-20C0-410E-BEDA-7ED416AECC2A}" =>
      { "name" => "Microsoft.WindowsDefender ", "path" => "Control Panel: Windows Defender " },
    "{4026492F-2F69-46B8-B9BF-5654FC07E423}" =>
      { "name" => "Microsoft.WindowsFirewall ", "path" => "Control Panel: Windows Firewall " },
    "{5ea4f148-308c-46d7-98a9-49041b1dd468}" => {
                                                 "name" => "Microsoft.MobilityCenter ",
                                                 "path" => "Control Panel: Windows Mobility Center "
                                                },
    "{E95A4861-D57A-4be1-AD0F-35267E261739}" =>
      { "name" => "Microsoft.WindowsSideShow ", "path" => "Control Panel: Windows SideShow " },
    "{36eef7db-88ad-4e81-ad49-0e313f0c35f8}" =>
      { "name" => "Microsoft.WindowsUpdate ", "path" => "Control Panel: Windows Update " },
    "{7A979262-40CE-46ff-AEEE-7884AC3B6136}" =>
      { "name" => "AddHardware ", "path" => "Control Panel (Vista): Add Hardware " },
    "{F2DDFC82-8F12-4CDD-B7DC-D4FE1425AA4D}" => {
                                     "name" => "AudioDevicesAndSoundThemes (Vista) - Sound (Win 7)",
                                     "path" => "Control Panel: Sound "
    },
    "{B98A2BEA-7D42-4558-8BD1-832F41BAC6FD}" => {
                     "name" => "BackupAndRestoreCenter (Vista) Microsoft.BackupAndRestore (Win 7) ",
                     "path" => "Control Panel (Vista): Backup and Restore Center "
    },
    "{3e7efb4c-faf1-453d-89eb-56026875ef90}" =>
      { "name" => "GetProgramsOnline ", "path" => "Control Panel (Vista): Windows Marketplace " },
    "{A0275511-0E86-4ECA-97C2-ECD8F1221D08}" => {
                                             "name" => "InfraredOptions (Vista) - Infrared (Win 7)",
                                             "path" => "Control Panel (Vista): Infrared "
    },
    "{F82DF8F7-8B9F-442E-A48C-818EA735FF9B}" => {
                   "name" => "PenAndInputDevices (Vista) - PenAndTouch (Win 7)",
                   "path" => "Control Panel (Vista): Pen and Input Devices - (Win 7) Pen And Touch "
    },
    "{40419485-C444-4567-851A-2DD7BFA1684D}" => {
                                   "name" => "PhoneAndModemOptions (Vista) - PhoneAndModem (Win 7)",
                                   "path" => "Control Panel: Phone and Modem "
    },
    "{2227A280-3AEA-1069-A2DE-08002B30309D}" =>
      { "name" => "Printers ", "path" => "Control Panel (Vista): Printers " },
    "{FCFEECAE-EE1B-4849-AE50-685DCF7717EC}" => {
                                   "name" => "ProblemReportsAndSolutions ",
                                   "path" => "Control Panel (Vista): Problem Reports and Solutions "
    },
    "{62D8ED13-C9D0-4CE8-A914-47DD628FB1B0}" => {
           "name" => "RegionalAndLanguageOptions (Vista) - RegionAndLanguage (Win 7)",
           "path" =>
             "Control Panel (Vista): Regional and Language Options - (Win 7) Regional and Language "
    },
    "{087DA31B-0DD3-4537-8E23-64A18591F88B}" =>
      { "name" => "SecurityCenter ", "path" => "Control Panel (Vista): Windows Security Center " },
    "{58E3C745-D971-4081-9034-86E34B30836A}" => {
          "name" => "SpeechRecognitionOptions (Vista) - SpeechRecognition (Win 7)",
          "path" => "Control Panel (Vista): Speech Recognition Options - (Win 7) Speech Recognition"
    },
    "{CB1B7F8C-C50A-4176-B604-9E24DEE8D4D1}" => {
                           "name" => "WelcomeCenter (Vista) - GettingStarted (Win 7)",
                           "path" => "Control Panel (Vista): Welcome Center (Win 7) Getting Started"
    },
    "{37efd44d-ef8d-41b1-940d-96973a50e9e0}" => {
                   "name" => "WindowsSidebarProperties (Vista) - DesktopGadgets (Win 7 and later) ",
                   "path" => "Control Panel (Vista): Windows Sidebar Properties "
    },

    # other GUID
    '{2559A1F4-21D7-11D4-BDAF-00C04F60B9F0}' => { 'name' => 'Internet', 'path' => 'VIRTUAL' },

    # GUID's gathered from here
    '{5D601655-6D54-4384-B52C-17EC5385FBBD}' => { 'name' => 'iTunes',        'path' => 'VIRTUAL' },
    '{1D14373E-7970-4F2F-A467-ACA4F0EA21E3}' => { 'name' => 'Google Earth',  'path' => 'VIRTUAL' },
    '{0CE1A6C0-F3F7-49E6-8F9D-2431F9827441}' => { 'name' => 'Guitar Hero 2', 'path' => 'VIRTUAL' },
    '{8355F970-601D-442D-A79B-1D7DB4F24CAD}' =>
      { 'name' => 'Apple Mobile Device Support', 'path' => 'VIRTUAL' },
    '{89F4137D-6C26-4A84-BDB8-2E5A4BB71E00}' =>
      { 'name' => 'Microsoft Silverlight', 'path' => 'VIRTUAL' },
    '{A06275F4-324B-4E85-95E6-87B2CD729401}' =>
      { 'name' => 'Windows Defender', 'path' => 'VIRTUAL' },
    '{B7050CBDB2504B34BC2A9CA0A692CC29}' => { 'name' => 'DivX Web Player', 'path' => 'VIRTUAL' },
    '{B13A7C41581B411290FBC0395694E2A9}' => { 'name' => 'DivX Converter',  'path' => 'VIRTUAL' },
    '{BBBCAE4B-B416-4182-A6F2-438180894A81}' => { 'name' => 'Napster',   'path' => 'VIRTUAL' },
    '{C78EAC6F-7A73-452E-8134-DBB2165C5A68}' => { 'name' => 'QuickTime', 'path' => 'VIRTUAL' },
    '{D32470A1-B10C-4059-BA53-CF0486F68EBC}' =>
      { 'name' => 'Kodak EasyShare Software', 'path' => 'VIRTUAL' },
    '{DDBB28C8-B2AA-45A1-8DCE-059A798509FB}' =>
      { 'name' => 'MobileMe Control Panel', 'path' => 'VIRTUAL' },
    '{9F7FC79B-3059-4264-9450-39EB368E3225}' =>
      { 'name' => 'Microsoft Digital Image Library 9 - Blocker', 'path' => 'VIRTUAL' },

);

sub get_win_tz($) {
    my $tz_check = shift;

    if (defined $known_timezone_transforms{"$tz_check"}) {
        return $known_timezone_transforms{"$tz_check"};
    }
    else {
        return 0;
    }
}

#	guid_exists
#
# A simple subroutine that check if a user supplied GUID exists in the known
# GUID table.
#
# @param guid A guid in the form of {HEX}
# @return Either true or false (0 or 1) indicating whether or not the GUID exists in the table
sub guid_exists($) {
    my $guid = shift;

    return defined $known_guids{"$guid"};
}

#	get_guid_path
#
# A simple subroutine that returns a string containing a
# translated version of the GUID of a known folder
#
# @param guid A guid in the form of {HEX}
# @return A string containing the display name and default path of the GUID
sub get_guid_path($) {
    my $guid = shift;
    my $path;

    if (guid_exists($guid)) {
        return '[' . $known_guids{"$guid"}->{'name'} . '] ' . $known_guids{"$guid"}->{'path'};
    }
    else {
        return 0;
    }
}

1;
