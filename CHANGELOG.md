# Changelog
* v1.8
    * added ability to parse Nexpose "XML Export"
    * added ability to parse Nessus ".nessus" files
    * added set() to iplist to ensure unique only
* v1.7.0
    * added `-w` medusa debug option
    * updated to v1.7.0 for auto builds
* v1.6.9
    * merged combo option and other fixes from @c-f (thank you)
    * added medusa verbosity `-v 1-6`
    * adjusted multiprocess buffer
    * updated some wordlists
    * updated readme
    * fixed MacOS subprocess arguments not being passed
* v1.6.8
    * added option to supress large banner
* v1.6.7
    * Check for wordlist in local directory
* v1.6.6
    * Integrated JSON support thanks to c-f
* v1.6.5
    * updated for python3 compatibility
    * switched to ElementTree XML API
    * rewrote xml parsing and fixed bugs
    * updated wordlists
* v1.6.4
    * use dictionary for name conversion
* v1.6.3
    * changes default smtp values
* v1.6.2
    * added file and path error checking
    * smtp auth args added
    * enabled piping medusa errors out
* v1.6.1
    * added output folder location verbage
    * -m dumps modules available
    * error checking when loading file
* v1.6.0
    * added support for SNMP
* v1.5.3
    * adjustments to wordlists
* v1.5.2
    * change tmp and output directory behavior
* v1.5.1
    * added check for no services
* v1.5
    * added interactive mode
* v1.4
    * added ability to use nmap XML
* v1.3
    * added the ability to stop on success
    * added the ability to reference custom userlists and passlists
    * added the ability to specify specific users & passwords
