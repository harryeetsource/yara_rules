rule DridexShellcode {
    meta:
        description = "Detects Dridex stager shellcode instructions"
        author = "Harrison Edwards"
        date = "2024-11-13"
        version = "2.3"

    strings:
        $sequence1 = { 48 85 d2 0f 84 ?? ?? ?? ?? 48 }      // dec eax; test edx, edx; je <offset>; dec eax
        $sequence2 = { 83 ec 20 89 74 24 20 }               // sub esp, 0x20; mov dword ptr [esp + 0x20], esi
        $sequence3 = { 8b 4a 08 45 33 c0 }                  // mov ecx, dword ptr [edx + 8]; inc ebp; xor eax, eax
        $sequence4 = { ff 97 d8 04 00 00 48 ff ce }         // call dword ptr [edi + 0x4d8]; dec eax; dec esi
        $sequence5 = { 8b 8f 30 04 00 00 33 d2 ff 97 c0 04 00 00 } // mov ecx, dword ptr [edi + 0x430]; xor edx, edx; call dword ptr [edi + 0x4c0]
        $sequence6 = { 85 c0 74 25 48 83 64 24 38 00 }      // test eax, eax; je <offset>; dec eax; and dword ptr [esp + 0x38], 0

        $push_stack_adjust = { 57 48 83 ec 20 }             // push edi; dec eax; sub esp, 0x20
        $dec_mov_sequence = { 48 89 5c 24 08 48 89 74 24 20 } // dec eax; mov dword ptr [esp + 8], ebx; dec eax; mov dword ptr [esp + 0x20], esi
        $conditional_jump_memory = { 85 d2 0f 84 ?? ?? ?? ?? 48 89 74 24 20 } // test edx, edx; je <relative address>; dec eax; mov dword ptr [esp + 0x20], esi
        $lea_stack_manipulation = { 8d 44 24 38 48 8d 54 24 40 } // lea eax, [esp + 0x38]; dec eax; lea edx, [esp + 0x40]
        $ret_int3 = { c3 cc }                                  // ret; int3
        $cmp_jne_sequence = { 81 3e 50 45 00 00 75 ?? }         // cmp dword ptr [esi], 0x4550; jne <relative address>

    condition:
        10 of them
}
