title: Dridex Process Pattern
id: e6eb5a96-9e6f-4a18-9cdd-642cfda21c8e
status: stable
description: Detects typical Dridex process patterns
references:
    - https://app.any.run/tasks/993daa5e-112a-4ff6-8b5a-edbcec7c7ba3
author: Florian Roth, oscd.community
date: 2019/01/10
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055
    - attack.discovery
    - attack.t1135
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\svchost.exe'
        CommandLine|contains|all:
            - 'C:\Users\'
            - '\Desktop\'
    selection2:
        ParentImage|endswith: '\svchost.exe'
    selection3:
        Image|endswith: '\whoami.exe'
        CommandLine|contains: 'all'
    selection4:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'view'
    condition: selection1 or selection2 and (selection3 or selection4)
falsepositives:
    - Unlikely
level: critical
