rule pe_file
{
	meta:
		description = "PE file 'MZ' header as string"
    
	strings:
		$pe = "MZ"

	condition:
		$pe at 0
}
