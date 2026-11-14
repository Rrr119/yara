/*
    Rules used by tests/test-perf.sh. They intentionally exercise two opposite
    shapes: string matching work and condition evaluation work.
*/

rule strings_heavy : perf_strings
{
    meta:
        author = "perf-test"
        severity = "low"

    strings:
        $a00 = "AA00"
        $a01 = "AA01"
        $a02 = "AA02"
        $a03 = "AA03"
        $a04 = "AA04"
        $a05 = "AA05"
        $a06 = "AA06"
        $a07 = "AA07"
        $a08 = "AA08"
        $a09 = "AA09"
        $a10 = "AA10"
        $a11 = "AA11"
        $a12 = "AA12"
        $a13 = "AA13"
        $a14 = "AA14"
        $a15 = "AA15"
        $a16 = "AA16"
        $a17 = "AA17"
        $a18 = "AA18"
        $a19 = "AA19"
        $a20 = "AA20"
        $a21 = "AA21"
        $a22 = "AA22"
        $a23 = "AA23"
        $a24 = "AA24"
        $a25 = "AA25"
        $a26 = "AA26"
        $a27 = "AA27"
        $a28 = "AA28"
        $a29 = "AA29"
        $a30 = "AA30"
        $a31 = "AA31"

    condition:
        any of them
}

rule conditions_heavy : perf_conditions
{
    meta:
        author = "perf-test"
        severity = "high"

    condition:
        for all i in (1..10000000) : (i >= 1)
}
