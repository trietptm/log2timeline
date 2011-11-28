##########################################################################################
#	log2timeline
##########################################################################################
# This script provides bash completion for log2timeline
#
# Author: Kristinn Gudjonsson
# Date : 24/08/11
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


_log2timeline()
{
	local cur prev opts
	COMPREPLY=()
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	opts="-s -skew -m -detail -d -f -format -x -u -upgrade -name -o -output -l -w -write -z -zone -Z -Zone -r -recursive -p -preprocess -log -c -calculate -x -exclude -t -temp -args -v -verbose -V -Version -h -help -?"
	
	# check the previous option/parameter
	case "$prev" in
	-f|-format)
		cur=`_get_cword`
		local moguleikar=$( for x in `log2timeline -f list | awk '/[a-z]/ {print $1}' | grep -v Available | grep -v Name | grep -v Use | sed -e 's/,//g' | sort -u`; do echo ${x}; done )

		# check if there is a comma in the option (hence a list)
		#if [ x`echo ${cur}` == "x," ]
		if [ `echo ${cur} | grep -c ','` == "0" ]
		then
			# then we don't have a comma, hence the first option
			COMPREPLY=( $(compgen -W "${moguleikar} list all guess" -- "$cur" ) )
		else
			# now we have a comma, let's complete the last word
			local list=`echo ${cur} | awk -F ',' '{for (i=1; i<NF; i++) printf "%s,",$i}'` 
			COMPREPLY=($( compgen -P $list -W '${moguleikar}' -- "`echo ${cur} | awk -F ',' '{print $NF}' | sed -e 's/-//'`" ) )
		fi


#		COMPREPLY=( $(compgen -W "altiris analog_cache apache2_access  apache2_error chrome \
#		encase_dirlisting evt  evtx  exif  ff_bookmark  firefox2  firefox3  ftk_dirlisting \
#		generic_linux iehistory  iis  isatxt  jp_ntfs_change  l2t_csv  mactime  mcafee  \
#		mcafeefireup mcafeehel mcafeehs mft  mssql_errlog ntuser  opera  oxml  pcap  pdf \
#		prefetch  recycler  restore  safari  sam  security setupapi  skype_sql  software  \
#		sol  squid  syslog  system  tln  volatility  win_link wmiprov  xpfirewall \
#		all guess linux web webhist win7 win7_no_reg winsrv winvista winxp winxp_no_reg" -- "$cur"  ))
		return 0
		;;
	-s|-skew)
		cur=`_get_cword`
		return 0
		;;
	-m)
		return 0
		;;
	-name|-n)
		return 0
		;;
	-o|-output)
		cur=`_get_cword`
		local moguleikar=$( for x in `log2timeline -o list | sed -e '1,3d' | awk '{print $1}' `; do echo ${x}; done )
		COMPREPLY=( $(compgen -W "${moguleikar} list" -- "$cur" ) )
		#COMPREPLY=( $(compgen -W "beedocs  cef  cftl  csv  mactime  mactime_l  simile  sqlite  tab  tln  tlnx" -- "$cur"  ))
		return 0
		;;
	-w|-write)
		_filedir 
		return 0
		;;
	-z|-zone|-Z|-Zone)
		cur=`_get_cword`
		local moguleikar=$( for x in `log2timeline -z list | tail -n +5`; do echo ${x}; done )

		COMPREPLY=( $(compgen -W "${moguleikar} local list" -- "$cur" ) )
		return 0
		;;
	-t|-temp)
		_filedir -d
		return 0	
		;;
	-l|-log)
		_filedir
		return 0
		;;
	-e|-exclude)
		return 0
		;;

	esac

	# check current one
	case "$cur" in
	-*)
		COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
		return 0
		;;
	*)
		_filedir
		return 0
		;;
	esac

}
complete -F _log2timeline log2timeline


