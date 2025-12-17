In the attached VM, the folder sent by McSkidy has been downloaded to /home/ubuntu/Downloads/easter. We will be using this folder to run our YARA rules against.
## YARA Overview
built to identify and classify malware by searching for unique patterns, the digital fingerprints left behind by attacker



- **Speed**: quickly scans large sets of files or systems to identify suspicious ones.
- **Flexibility**: detects everything from text strings to binary patterns and complex logic.
- **Control**: lets analysts define exactly what they consider malicious.
- **Shareability**: rules can be reused and improved by other defenders across kingdoms.
- **Visibility**: helps connect scattered clues into a clear picture of the attack.

```YARA
rule TBFC_KingMalhare_Trace
{
    meta:
        author = "Defender of SOC-mas"
        description = "Detects traces of King Malhare’s malware"
        date = "2025-10-10"
    strings:
        $s1 = "rundll32.exe" fullword ascii
        $s2 = "msvcrt.dll" fullword wide
        $url1 = /http:\/\/.*malhare.*/ nocase
    condition:
        any of them
}
```


**meta section** contains fields like author, description, and date. These fields are not required, but they are highly recommended. They help you and other defenders understand what the rule is about, who created it, and when it was written. When your collection of YARA rules grows, having clear metadata will save you time; without it, finding or updating the right rule can quickly become a challenge.


## Strings 
strings are the clues that YARA searches for when scanning files, memory, or other data sources.  
They represent the signatures of malicious activity in fragments of text, bytes, or patterns that can reveal the presence of King Malhare's code

**Text strings**
	 YARA helps defenders counter these obfuscation methods with a few powerful modifiers that extend the capabilities of text strings:

- **Case-insensitive strings - nocase  
    **By default, YARA matches text exactly as written. Adding the `nocase` modifier makes the match ignore letter casing, so "Christmas", "CHRISTMAS", or "christmas" will all trigger the same result.

```php
strings:
    $xmas = "Christmas" nocase
```

- **Wide-character strings - wide, ascii**  
    Many Windows executables use two-byte Unicode characters. Adding `wide` tells YARA to also look for this format, while `ascii` enforces a single-byte search. You can use both together:

```php
strings:
    $xmas = "Christmas" wide ascii
```

- **XOR strings - xor  
    **Malhare's agents often XOR-encode text to hide it from scanners. Using the `xor` modifier, YARA automatically checks all possible single-byte XOR variations of a string - revealing what attackers tried to conceal.

```php
strings:
    $hidden = "Malhare" xor
```

- **Base64 strings - base64, base64wide**  
    Some malware encodes payloads or commands in Base64. With these modifiers, YARA decodes the content and searches for the original pattern, even when it’s hidden in encoded form.

```php
strings:
    $b64 = "SOC-mas" base64
```

Each of these modifiers makes your rule smarter and more resilient, ensuring that even when King Malhare disguises his code, the defenders of TBFC can still uncover the truth.

**Hexadecimal strings**
Hex strings allow YARA to search for specific byte patterns, written in hexadecimal notation  This is useful when defenders need to detect malware fragments like file headers, shellcode, or binary signatures that can't be represented as plain text


**Regular expression strings**
Regex allows defenders to write flexible search patterns that can match multiple variations of the same malicious string.

```php
rule TBFC_Malhare_RegexDetect
{
    strings:
        $url = /http:\/\/.*malhare.*/ nocase
        $cmd = /powershell.*-enc\s+[A-Za-z0-9+/=]+/ nocase

    condition:
        $url and $cmd
}
```

 Regex strings are powerful but should be used carefully; they can match a wide range of data and may slow down scans if written too broadly.


**Conditions**

**Conditions**

Now that the defenders of TBFC know how to describe what to look for using strings, it's time to learn when YARA should decide that a threat has been found. That logic lives inside the condition section, the heart of every YARA rule. The condition tells YARA when the rule should trigger based on the results of all the string checks. Think of it as the final decision point, the moment when the system confirms: "Yes, this looks like King Malhare's code." Let's look at a few basic examples defenders use in their daily missions.  
  
**Match a single string**  
The simplest condition, the rule triggers if one specific string is found. For example, the variable xmas.

```php
condition:
    $xmas
```

**Match any string  
**When multiple strings are defined, the rule can be configured to trigger as soon as any one of them is found:

```php
condition:
    any of them
```

This approach is useful for detecting early signs of compromise; even a single matching clue can be enough to raise attention.  
  
**Match all strings  
**To make the rule stricter, you can require that all defined strings appear together:

```php
condition:
    all of them
```

This approach reduces false positives; YARA will only flag a file if every indicator matches.

**Combine logic using: and, or, not  
**Defenders often need more control over how rules behave. Logical operators let you combine multiple checks into one condition, just like building a small defensive strategy.

```php
condition:
    ($s1 or $s2) and not $benign
```

This means the rule will trigger if either $s1 or $s2 is found, but not $benign. In other words: detect suspicious code, but ignore harmless system files.  
  
**Use comparisons like: filesize, entrypoint, or hash  
**YARA can also check file properties, not just contents. For example, you can detect files that are unusually small or large, a common trick used by King Malhare to disguise his payloads.

```php
condition:
    any of them and (filesize < 700KB)
```

Here, the rule will trigger only when one of the strings matches and the file size is smaller than 700KB.  
We've now reviewed the main examples of Conditions, and it's time to move on to the practical use cases where these rules come to life.

## YARA Study Use Cases

The evil kingdom of Malhare used a trojan known as IcedID to steal credentials from systems. McSkidy's analysts discovered that the malicious files spread across Wareville shared a common signature, the same MZ header found in executable malware used by the Dark Kingdom. These samples were small, lightweight loaders designed to infiltrate systems and later summon more dangerous payloads. Let's write our YARA rule.

```php
rule TBFC_Simple_MZ_Detect
{
    meta:
        author = "TBFC SOC L2"
        description = "IcedID Rule"
        date = "2025-10-10"
        confidence = "low"

    strings:
        $mz   = { 4D 5A }                        // "MZ" header (PE file)
        $hex1 = { 48 8B ?? ?? 48 89 }            // malicious binary fragment
        $s1   = "malhare" nocase                 // story / IOC string

    condition:
        all of them and filesize < 10485760     // < 10MB size
}
```


# Solution 

We create this yara rule with regex string 
```
rule TBFC_KingMalhare_Trace
{
    meta:
        author = "Defender of SOC-mas"
        description = "Detects traces of King Malhare ^`^ys malware"
        date = "2025-10-10"
    strings:
        $s1 = /TBFC:[A-Za-z0-9]+/
    condition:
        any of them
}


```

We run using this command to recursively quickly run the yara rule and output the string matches 

`yara -r -f -s THM.yar /home/ubuntu/Downloads/easter/`