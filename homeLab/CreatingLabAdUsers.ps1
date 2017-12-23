




#region functions
function New-GeneratedPerson
{
    param (
        [parameter()][int]$count = 1,
        [parameter()][ValidateSet("Male","Female")][string]$gender
    )

    ####

    $generatorUri = "https://randus.org/api.php"
    $generatedUsers = @()

    ####

    for ($i = 1; $generatedUsers.Count -lt $count; $i++)
    {
        $user = Invoke-RestMethod $generatorUri

        switch ($gender)
        {
            "Male"   {If ($user.gender -eq "m") {$generatedUsers += ($user.lname + " " + $user.fname + " " + $user.patronymic)}}
            "Female" {If ($user.gender -eq "w") {$generatedUsers += ($user.lname + " " + $user.fname + " " + $user.patronymic)}}
            default  {$generatedUsers += ($user.lname + " " + $user.fname + " " + $user.patronymic)}
        }
        Start-Sleep -m 50
    }
    return $generatedUsers
}
function Convert-ToLat 
{
    Param
    (
        [parameter(Mandatory = $true)][string]$inString
    )

    $translitTable = @{ 
    [char]'à' = "a"
    [char]'À' = "A"
    [char]'á' = "b"
    [char]'Á' = "B"
    [char]'â' = "v"
    [char]'Â' = "V"
    [char]'ã' = "g"
    [char]'Ã' = "G"
    [char]'ä' = "d"
    [char]'Ä' = "D"
    [char]'å' = "e"
    [char]'Å' = "E"
    [char]'¸' = "e"
    [char]'¨' = "E"
    [char]'æ' = "zh"
    [char]'Æ' = "Zh"
    [char]'ç' = "z"
    [char]'Ç' = "Z"
    [char]'è' = "i"
    [char]'È' = "I"
    [char]'é' = "y"
    [char]'É' = "Y"
    [char]'ê' = "k"
    [char]'Ê' = "K"
    [char]'ë' = "l"
    [char]'Ë' = "L"
    [char]'ì' = "m"
    [char]'Ì' = "M"
    [char]'í' = "n"
    [char]'Í' = "N"
    [char]'î' = "o"
    [char]'Î' = "O"
    [char]'ï' = "p"
    [char]'Ï' = "P"
    [char]'ð' = "r"
    [char]'Ð' = "R"
    [char]'ñ' = "s"
    [char]'Ñ' = "S"
    [char]'ò' = "t"
    [char]'Ò' = "T"
    [char]'ó' = "u"
    [char]'Ó' = "U"
    [char]'ô' = "f"
    [char]'Ô' = "F"
    [char]'õ' = "kh"
    [char]'Õ' = "KH"
    [char]'ö' = "ts"
    [char]'Ö' = "Ts"
    [char]'÷' = "ch"
    [char]'×' = "Ch"
    [char]'ø' = "sh"
    [char]'Ø' = "Sh"
    [char]'ù' = "sch"
    [char]'Ù' = "Sch"
    [char]'ú' = ""		# "``"
    [char]'Ú' = ""		# "``"
    [char]'û' = "y"		# "y`"
    [char]'Û' = "Y"		# "Y`"
    [char]'ü' = ""		# "`"
    [char]'Ü' = ""		# "`"
    [char]'ý' = "e"		# "e`"
    [char]'Ý' = "E"		# "E`"
    [char]'þ' = "yu"
    [char]'Þ' = "Yu"
    [char]'ÿ' = "ya"
    [char]'ß' = "Ya"
    }

    $outChars = ""

    foreach ($char in $inChars = $inString.ToCharArray())
        {
            if ($translitTable[$c] -cne $Null ) 
            {
                $outChars += $translitTable[$c]
            }
            else
            {
                $outChars += $c
            }
        }

    return $outChars
}
function Set-Login
{
    Param 
    (
        [parameter(Mandatory = $true)][string]$fullName
    )

    $enInName 		= ((Convert-ToLat(($fullName -split " ")[1])).ToLower())[0]
    $enInMidName 	= ((Convert-ToLat(($fullName -split " ")[2])).ToLower())[0]
    $enSN 			= (Convert-ToLat(($fullName -split " ")[0])).toLower()
    $login = $enSN + "." + $enInName + $enInMidName

    return $login
}
function New-SWRandomPassword 
{
    <#
    .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
       New-SWRandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8  and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Will generate four passwords, each with a length of between 8 and 12 chars.
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString
    .EXAMPLE
       New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
       3ABa

       Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
       the string specified with the parameter FirstChar
    .OUTPUTS
       [String]
    .NOTES
       Written by Simon WÃ¥hlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
       Generates random passwords
    .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!"#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}
function New-LabAdUser
{
    Param
    (
        [parameter(Madatory = $true,ValueFromPipeline=$true)][string]$fullName,
        [parameter()][string]$organizationalUnit,
        [parameter()][string]$title,
        [parameter()][string]$company,
        [parameter()][string]$department
    )

    $enabled = $true
    $displayName = $fullName
    $sn = ($fullName -split " ")[0]
    $givenName = ($fullName -split " ")[1]
    $middleName = ($fullName -split " ")[2]
    $sAMAccountName = Set-Login $fullName
    $plainTextPwd = New-SWRandomPassword
    $password = $plainTextPwd | ConvertTo-SecureString -AsPlainText -Force
    $description = $plainTextPwd

    If ($organizationalUnit) {$path = $organizationalUnit} else {$path = (Get-ADDomain).UsersContainer}

    try
    {
        $existUser = Get-ADUser -LDAPFilter "(sAMAccountName=$sAMAccountName)" -ErrorAction Stop -ErrorVariable eaExistUsers
    }
    catch
    {
    
    }

    If (!$existUser)
    {
        New-ADUser -SamAccountName $sAMAccountName `
                    -AccountPassword $password `
                    -Enabled $enabled `
                    -ChangePasswordAtLogon $false `
                    -Path $path `
                    -Name $fullName `
                    -DisplayName $fullName `
                    -GivenName $givenName `
                    -Surname $sn `
                    -Description $plainTextPwd `
                    -OtherAttributes @{
                        middleName = $middleName
                        company = $company
                    }
        
        Start-Sleep 5

        If ($title) {Set-ADUser -SamAccountName $sAMAccountName -Title $title}
        If ($department) {Set-ADUser -SamAccountName $sAMAccountName -Department $department}

    }

}

#endregion


