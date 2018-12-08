# EnterpriseWifiPasswordRecover
This is a tool that recovers WPA2 Enterprise Wifi Credentials from a machine.

# What does this do?
 - This tool recovers enterprise WPA2 MGT PEAP credentials from Windows machines
 - This repo has basic documentation on the format Windows stores the credentials in

# Please note:
 - This solution has only been tested successfully on Windows 10. Additional testing to verify if this solution works on older versions of Windows is required.

# How do I use this?
 - Compile it yourself using Visual Studio Community Edition (free download)
 - Alternately, grab the latest release from the releases section
 - The executable needs to be run multiple times
 - You need to run the executable as the `NT AUTHORITY\SYSTEM` user to decrypt the first layer of encryption
 - After that, it needs to be run in the context of the user who owns the WiFi network

# How do I run the executable as NT AUTHORITY\SYSTEM ?
 - Download `psexec` which is part of the `Sysinternals Suite` from Microsoft
 - Open an administartive command prompt window
 - Type the following to get a system level command prompt `psexec -s -i cmd`
 - Type `whoami` to confirm that the command prompt is running as system
 - Execute the application using the system level command prompt

# How are WPA2 MGT (Enterprise PEAP) Credentials stored in Windows 10?
 - There are a few edge cases, such as accessing a Wireless profile via the lock screen, however, this is the most typical case.
 - A user (e.g. Administrator) is logged into a PC.
 - The user connects to the WiFi access point and enters their credentials
 - The following ondisk directory structure is created:
   - `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{interfaceID}\{profileID}.xml`
 - The following registry entry is created to store the enterprise credentials
   - `HKEY_CURRENT_USER\Software\Microsoft\Wlansvc\UserData\Profiles\{profileID}\`
   - Sometimes it is stored in: `HKEY_LOCAL_MACHINE\Software\Microsoft\Wlansvc\UserData\Profiles\{profileID}\`
   - Sometimes it is stored in: `HKEY_LOCAL_MACHINE\Software\Microsoft\Wlansvc\Profiles\{profileID}\`
   - The "MSMUserData" binary value contains the encrypted credentials
   - In Windows 10, the first layer can be decrypted using the following C# code, run in the context of the system user:
     - `ProtectedData.Unprotect(<data>, null, DataProtectionScope.LocalMachine);`
   - This will decrypt and the result will be a blog of binary data, looking at the data, it's easy to spot the domain and username in clear text.
   - The username comes directly after the following bytes `{ 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 }`, and terminates after a null byte if it is encrypted.
     - If the blob isn't encrypted with the user's credentials, then the username will be after `{ 0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 }` in plain text, then a series of null bytes, followed by a clear text password, then a series of null bytes and possibly a domain, if you reach `0x01` then there is no domain.
   - The domain comes after a bunch of the username, there will be a series of null bytes. If you reach a `0xE6` character, then there is no domain present in the credentials.
   - The password is then encrypted again using the same C# call, however, it is encrypted using the context of the user who first connected to the wireless network (or the user who first logged in after the connection was made)
   - The encrypted password section starts with (and includes) the following bytes `{ 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01 }`
   - Decrypting this section gives the password in clear text, it also appears as though some additional null bytes may be present at the end, so they should be stripped.

# What about WPA2 PSK (Pre Shared Key)?
 - You don't need a special tool to recover those
 - Open an admin command prompt
 - Type: `netsh wlan show profile` to list all of the wireless profiles
 - Type: `netsh wlan show profile name="<name from the list of profiles>" key=clear` which will reveal the PSK
 - For reference, the pre shared key is stored directly in the following location: `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{interfaceID}\{profileID}.xml`
 - The pre shared key needs to be converted from HEX into binary format, and then it can be decrypted using `ProtectedData.Unprotect(<data>, null, DataProtectionScope.LocalMachine);` in the context of a system user.

# What if I need a certificate to connect to a Wireless network?
 - I don't know -- more research to come
 - The certificate might actually be stored in the same blob

# What about Windows 7 or earlier?
 - I need to do more research to figure this out
 - I made the program generic enough that it should catch the keys from earlier versions of Windows, however, I haven't officially tested it
 - I think they _may_ be stored in `HKEY_LOCAL_MACHINE` instead of `HKEY_CURRENT_USER`, but I haven't confirmed this yet

# I have made an improvement, what do I do?
 - Make a pull request on the repo
 - I will review the pull request
 - If it's good to go, I will merge it
