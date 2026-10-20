/*
 * Benign example rule shipped so the YARA path has something to compile.
 * Replace with your own ruleset. This flags only a generic PE marker and is
 * intentionally low-signal; it is not a detection rule for any real family.
 */

rule example_pe_marker
{
    meta:
        author = "MalSift example"
        description = "Flags the MZ DOS header. Example only; replace with real rules."
        severity = "info"
    strings:
        $mz = { 4D 5A }            // "MZ"
    condition:
        $mz at 0
}

rule example_high_entropy_hint
{
    meta:
        author = "MalSift example"
        description = "Example: presence of a common packer section name."
        severity = "info"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        any of them
}
