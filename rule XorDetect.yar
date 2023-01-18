rule XorDetect
{
    strings:
        $xor_string = "This program cannot" xor(0x01-0xff)
    condition:
    $xor_string
}