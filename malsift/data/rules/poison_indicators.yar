/*
 * Generic prompt-injection ("poison") indicators.
 *
 * These rules key on the STRUCTURE of text aimed at hijacking an LLM-based analyzer:
 * instruction-override phrasing, fake chat-template role headers, and spoofed prompt
 * delimiters. They deliberately contain no subject-matter / topic keyword lists.
 * A hit means "this sample carries text addressed to an AI analyzer", which is itself
 * an anti-analysis signal worth an analyst's attention.
 */

rule poison_instruction_override
{
    meta:
        author = "MalSift"
        description = "Instruction-override phrasing aimed at an LLM analyzer"
        severity = "medium"
    strings:
        $o1 = /ignore\s{1,4}(all\s{1,4})?(of\s{1,4})?(the\s{1,4}|your\s{1,4})?(previous|prior|above|preceding|earlier)\s{1,4}(instructions|prompts?|directives|rules)/ nocase ascii wide
        $o2 = /disregard\s{1,4}(all\s{1,4})?(the\s{1,4}|your\s{1,4})?(system|previous|prior|above)\s{1,4}(prompt|message|instructions|rules)/ nocase ascii wide
        $o3 = /forget\s{1,4}(all\s{1,4})?(your|the)\s{1,4}(previous\s{1,4}|prior\s{1,4})?(instructions|rules|guidelines)/ nocase ascii wide
        $o4 = /you\s{1,4}are\s{1,4}now\s{1,4}(a|an|in)\s{1,4}\w/ nocase ascii wide
        $o5 = /new\s{1,4}(system\s{1,4})?instructions?\s{0,3}:/ nocase ascii wide
        $o6 = /(do\s{1,4}not|don't|refuse\s{1,4}to)\s{1,4}(analy[sz]e|disassemble|classify|report\s{1,4}on)\s{1,4}(this|the)\s{1,4}(file|sample|binary|code|program|script)/ nocase ascii wide
    condition:
        any of them
}

rule poison_fake_role_header
{
    meta:
        author = "MalSift"
        description = "Chat-template role markers / fake role headers embedded in a sample"
        severity = "medium"
    strings:
        $r1 = "<|im_start|>" ascii wide
        $r2 = "<|im_end|>" ascii wide
        $r3 = /<\|(system|user|assistant)\|>/ nocase ascii wide
        $r4 = /\[\/?INST\]/ ascii wide
        $r5 = /<<\/?SYS>>/ ascii wide
        $r6 = /###\s{0,3}(system|instruction|response)\s{0,3}:/ nocase ascii wide
        $r7 = /[\r\n][ \t]{0,8}(system|assistant)[ \t]{0,3}:[ \t]{0,3}(you\s|ignore\s|from\s{1,3}now)/ nocase ascii wide
    condition:
        any of them
}

rule poison_delimiter_spoofing
{
    meta:
        author = "MalSift"
        description = "Spoofed prompt delimiters that try to close or reopen an analyzer's prompt"
        severity = "medium"
    strings:
        $d1 = "<|endoftext|>" ascii wide
        $d2 = /<\/?(system_prompt|system|instructions|user_input|tool_output)>/ nocase ascii wide
        $d3 = /(end|begin)\s{1,3}of\s{1,3}(the\s{1,3})?(system\s{1,3}prompt|instructions|user\s{1,3}input|untrusted\s{1,3}(data|content))/ nocase ascii wide
        $d4 = /[-=#]{3,}\s{0,3}(end|begin)\s{1,3}(of\s{1,3})?(the\s{1,3})?(system\s{1,3})?(prompt|instructions|system)\s{0,3}[-=#]{3,}/ nocase ascii wide
    condition:
        any of them
}
