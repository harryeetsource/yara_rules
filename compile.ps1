# Set the path to your YARA directory
$YaraDir = "C:\Users\HarrisonEdwards\Downloads\yara_rules-main\yara_rules-main"
# Set the output compiled rules file
$OutputRules = "C:\Users\HarrisonEdwards\Downloads\yara_rules-main\yara_rules-main\Compiled.yar"

# Get all .yar files in the directory
$YaraFiles = Get-ChildItem -Path $YaraDir -Filter *.yar -Recurse

# Construct the file paths for yarac command
$YaraFilesPaths = $YaraFiles.FullName -join " "

# Compile the YARA files into a compiled ruleset
$YaracPath = "C:\Users\HarrisonEdwards\Downloads\yara-v4.5.2-2326-win64\yarac64.exe"  # Modify this to point to your yarac executable
$Command = "$YaracPath $YaraFilesPaths $OutputRules"

Invoke-Expression $Command

if ($LASTEXITCODE -eq 0) {
    Write-Output "Compilation successful! Compiled ruleset saved to $OutputRules"
} else {
    Write-Output "Compilation failed. Check the YARA files for issues."
}
