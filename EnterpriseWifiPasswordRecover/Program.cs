using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace EnterpriseWifiPasswordRecover
{
    class Program
    {
        // The files we will store the output into
        public static string workingDirectory = System.IO.Directory.GetCurrentDirectory() + "/profiles/";
        public static string stage1Prefix = "stage1_";
        public static string stage2Prefix = "stage2_";
        public static string stage3Prefix = "decrypted_";
        public static string extension = ".txt";

        static void Main(string[] args)
        {
            // Ensure we have a profiles directory
            try
            {
                System.IO.Directory.CreateDirectory(workingDirectory);
            }
            catch
            {
                // do nothing
            }

            // Decrypting enterprise wifi passwords is done in 3 stages
            Stage1();   // Extract reg keys             Typically runas: SYSTEM (it will pickup the keys of every user)
            Stage2();   // Try to decrypt first layer   Typically runas: SYSTEM
            Stage3();   // Show creds, where possible   Typically runas: the user that owns the connection
        }

        // Retreive the payloads from registry
        public static void Stage1()
        {
            // The location where the magic is stored in the registry
            string keyName = @"Software\Microsoft\Wlansvc\UserData\Profiles\";
            string keyName2 = @"Software\Microsoft\Wlansvc\Profiles\";

            // Will contain a list of places to search in the registry for profiles
            List<RegistryKey> possibleKeys = new List<RegistryKey>();

            // Try access all other user's registries
            try
            {
                string[] allUsers = Registry.Users.GetSubKeyNames();

                for(int i=0; i<allUsers.Length; ++i)
                {
                    try
                    {
                        // Open up the user
                        RegistryKey possibleKey = Registry.Users.OpenSubKey(allUsers[i]);

                        // Try to open the store for wireless keys
                        possibleKeys.Add(possibleKey.OpenSubKey(keyName));
                        possibleKeys.Add(possibleKey.OpenSubKey(keyName2));
                    }
                    catch
                    {
                        // Key does not exist
                    }
                }
            }
            catch
            {
                // Error access users registry store
            }
            
            // Try to open the local machine entry
            try
            {
                possibleKeys.Add(Registry.LocalMachine.OpenSubKey(keyName));
                possibleKeys.Add(Registry.LocalMachine.OpenSubKey(keyName2));
            }
            catch
            {
                // Do nothing
            }

            // Try to open the current user entry
            try
            {
                possibleKeys.Add(Registry.CurrentUser.OpenSubKey(keyName));
                possibleKeys.Add(Registry.CurrentUser.OpenSubKey(keyName2));
            }
            catch
            {
                // Do nothing
            }

            // Try both registry locations
            for (int i = 0; i < possibleKeys.Count; ++i)
            {
                // Grab the registry location
                RegistryKey key = possibleKeys[i];
                
                if (key == null) continue;
                try
                {
                    // Grab every subkey in here, each profile has a subkey
                    string[] subKeys = key.GetSubKeyNames();
                    for (int j = 0; j < subKeys.Length; ++j)
                    {
                        // Open the subkey (a profile)
                        string subKey = subKeys[j];
                        RegistryKey subKey2 = key.OpenSubKey(subKey);

                        Console.WriteLine(subKey);

                        // Is there MSMUserData? This is where the gold is stored
                        byte[] theData = (byte[])subKey2.GetValue("MSMUserData", null);

                        if (theData != null)
                        {
                            // Write it to disk, this is stage1 extracted!
                            System.IO.File.WriteAllBytes(workingDirectory + "/" + stage1Prefix + subKey + extension, theData);
                            Console.WriteLine("Extracted stage1 for " + subKey);
                        }
                    }
                }
                catch
                {
                    // no permissions?
                }

            }
        }

        // Decrypt the overall package, this gets us the domain + username + encrypted password
        public static void Stage2()
        {
            string[] profiles;

            // Find a list of profiles in the profile directory we created in stage1
            try
            {
                profiles = System.IO.Directory.GetFiles(workingDirectory);
            }
            catch
            {
                // Failure
                Console.WriteLine("Didnt find any profiles :/");
                return;
            }

            // Loop over all the files
            for(int i=0; i<profiles.Length; ++i)
            {
                string profilePath = profiles[i];
                string profile = System.IO.Path.GetFileNameWithoutExtension(profilePath);

                // Is this a stage1 profile?
                if (!profile.Contains(stage1Prefix)) continue;
                profile = profile.Replace(stage1Prefix, "");

                try
                {
                    // Read in the data from this stage
                    byte[] data = System.IO.File.ReadAllBytes(profilePath);

                    // Try to decrypt it, and then store it into a stage2 file
                    try
                    {
                        byte[] unprotectedBytes = ProtectedData.Unprotect(data, null, DataProtectionScope.LocalMachine);
                        System.IO.File.WriteAllBytes(workingDirectory + "/" + stage2Prefix + profile + extension, unprotectedBytes);
                    }
                    catch
                    {
                        Console.WriteLine("Failed to decrypt " + profile + " - Run as SYSTEM or ORIGINAL USER!");
                    }
                }
                catch
                {
                    // Failed to read, continued
                    Console.WriteLine("Failed to read " + profile);
                    continue;
                }
            }
        }

        // Try to decrpyt the password, and extract username + domain
        public static void Stage3()
        {
            string[] profiles;

            try
            {
                profiles = System.IO.Directory.GetFiles(workingDirectory);
            }
            catch
            {
                // Failure
                Console.WriteLine("Didnt find any profiles :/");
                return;
            }

            // Loop over all the profiles in the profile directory we created in the previous steps
            for (int i = 0; i < profiles.Length; ++i)
            {
                string profilePath = profiles[i];
                string profile = System.IO.Path.GetFileNameWithoutExtension(profilePath);

                // Is this a stage2 decrypted payload?
                if (!profile.Contains(stage2Prefix)) continue;
                profile = profile.Replace(stage2Prefix, "");

                try
                {
                    // Try to decrypt everything, and print what we found
                    byte[] data = System.IO.File.ReadAllBytes(profilePath);
                    UsernameStore theStore = DecryptAll(data);
                    PrintUsernameStore(theStore);

                    // If we decrypted the password, store the result into a file
                    if(theStore.password != null && theStore.password.Length > 0)
                    {
                        // Generate the payload
                        string theOutput = profile + "\n";
                        theOutput += "Domain: " + theStore.domain + "\n";
                        theOutput += "Username: " + theStore.username + "\n";
                        theOutput += "Password: " + theStore.password + "\n";
                        
                        System.IO.File.WriteAllText(workingDirectory + "/" + stage3Prefix + profile + extension, theOutput);
                    }
                }
                catch
                {
                    // Failed to read, continued
                    Console.WriteLine("Failed to read " + profile);
                    continue;
                }
            }
        }

        public static int SigScan(byte[] hayStack, byte[] needle, int startAt = 0, bool invert = false)
        {
            // Try every position
            for (int i = startAt; i < hayStack.Length; ++i)
            {
                // Attempt to perform the match
                bool broken = false;
                for (int j = 0; j < needle.Length; ++j)
                {
                    if(invert)
                    {
                        // If there is a match, it's not the right signature
                        if (needle[j] == hayStack[i + j])
                        {
                            broken = true;
                            break;
                        }
                    } else
                    {
                        // If the bytes don't match, it's not the right signature
                        if (needle[j] != hayStack[i + j])
                        {
                            broken = true;
                            break;
                        }
                    }
                }

                if (!broken)
                {
                    // We found a full match!
                    return i;
                }
            }

            // No full match found
            return -1;
        }

        // Copies part of an existing byte[], or clones the whole thing
        public static byte[] Slice(byte[] data, int startIndex = -1, int endIndex = -1)
        {
            // Sanity checking / argument fixing
            if (startIndex < 0) startIndex = 0;
            if (endIndex < 0 || endIndex > data.Length) endIndex = data.Length;
            if (endIndex < startIndex) return new byte[0];

            // Allocate the memory for the new byte[] we will return
            int totalSize = endIndex - startIndex;
            byte[] toReturn = new byte[totalSize];

            // Copy the data into the new byte[]
            for(int i=0; i<totalSize; ++i)
            {
                toReturn[i] = data[i + startIndex];
            }

            return toReturn;
        }

        // Prints the creds stored in the UsernameStore structure
        public static void PrintUsernameStore(UsernameStore theStore)
        {
            Console.WriteLine("Found the following:");
            Console.WriteLine("Domain: " + theStore.domain);
            Console.WriteLine("Username: " + theStore.username);
            Console.WriteLine("Password: " + theStore.password);
        }

        // Tries to decrypt the given payload, and stores the result into the UsernameStore provided, or creates a new UsernameStore
        public static UsernameStore DecryptAll(byte[] toDecrypt, UsernameStore theStore = null)
        {
            // Ensure we have a store
            if (theStore == null) theStore = new UsernameStore();

            // Try to decrypt everything
            DecryptUsername(toDecrypt, theStore);
            DecryptPassword(toDecrypt, theStore);

            // Return it
            return theStore;
        }

        // Attempts to retreive the username and domain from the given payload
        public static UsernameStore DecryptUsername(byte[] toDecrypt, UsernameStore theStore = null)
        {
            // Used to find the start of the username / password blob
            byte[] searchForUsername = { 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
            byte[] searchForUsername2 = { 0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 };
            byte[] nullArray = { 0x00 };

            // Ensure we have a store for the username
            if (theStore == null) theStore = new UsernameStore();

            int usernameFieldStart = SigScan(toDecrypt, searchForUsername);
            if (usernameFieldStart != -1)
            {
                // Move to the start of the actual field
                usernameFieldStart += searchForUsername.Length;
                int usernameFieldEnd = SigScan(toDecrypt, nullArray, usernameFieldStart);

                if (usernameFieldEnd != -1)
                {
                    byte[] usernameField = Slice(toDecrypt, usernameFieldStart, usernameFieldEnd);
                    theStore.username = Encoding.ASCII.GetString(usernameField);

                    // Find the domain start
                    int domainFieldStart = SigScan(toDecrypt, nullArray, usernameFieldEnd + 1, true);

                    // Test if a domain was found, if we reached 0xE6, there was no domain present
                    if (domainFieldStart != -1 && toDecrypt[domainFieldStart] != 0xE6)
                    {
                        int domainFieldEnd = SigScan(toDecrypt, nullArray, domainFieldStart);

                        if (domainFieldEnd != -1)
                        {
                            // Copy the domain out
                            byte[] possibleDomainField = Slice(toDecrypt, domainFieldStart, domainFieldEnd);
                            theStore.domain = Encoding.ASCII.GetString(possibleDomainField);
                        }
                    }
                }
            }
            else
            {
                // Failed to find the blob, maybe it's not encrypted?
                
                usernameFieldStart = SigScan(toDecrypt, searchForUsername2);

                Console.WriteLine(usernameFieldStart);

                if(usernameFieldStart != -1)
                {
                    // Looks good?

                    // There will be some null bytes, skip until the end of those
                    usernameFieldStart += searchForUsername2.Length;
                    usernameFieldStart = SigScan(toDecrypt, nullArray, usernameFieldStart, true);

                    // Find where the username field ends
                    int usernameFieldEnd = SigScan(toDecrypt, nullArray, usernameFieldStart + 1);

                    byte[] usernameField = Slice(toDecrypt, usernameFieldStart, usernameFieldEnd);
                    theStore.username = Encoding.ASCII.GetString(usernameField);

                    // Keep searching, the password is probably here too!
                    int passowrdFieldStart = SigScan(toDecrypt, nullArray, usernameFieldEnd + 1, true);

                    if(passowrdFieldStart != -1)
                    {
                        int passwordFieldEnd = SigScan(toDecrypt, nullArray, passowrdFieldStart + 1);

                        if(passwordFieldEnd != -1)
                        {
                            byte[] passwordField = Slice(toDecrypt, passowrdFieldStart, passwordFieldEnd);
                            theStore.password = Encoding.ASCII.GetString(passwordField);

                            // Maybe there is a domain too?
                            int domainFieldStart = SigScan(toDecrypt, nullArray, passwordFieldEnd + 1, true);

                            if (domainFieldStart != -1)
                            {
                                int domainFieldEnd = SigScan(toDecrypt, nullArray, domainFieldStart + 1);

                                if(domainFieldEnd != -1)
                                {
                                    byte[] domainField = Slice(toDecrypt, domainFieldStart, domainFieldEnd);

                                    if(domainField[0] != 0x01)
                                    {
                                        theStore.domain = Encoding.ASCII.GetString(domainField);
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Failed to find username field!");
                }
            }

            return theStore;
        }

        // Attempt to decrypt the password field in the given payload, will store the password into the given UsernameStore, or create a new one
        public static UsernameStore DecryptPassword(byte[] toDecrypt, UsernameStore theStore = null)
        {
            if(theStore == null) theStore = new UsernameStore();

            // This is the signature of where the encrypted password starts
            byte[] searchForPassword = { 0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01 };

            // See if there is an encrypted password chunk present
            int passwordFieldStart = SigScan(toDecrypt, searchForPassword);
            if (passwordFieldStart != -1)
            {
                // A chunk was successfully found
                Console.WriteLine("Found encrypted password blob...");
                byte[] passwordBlob = Slice(toDecrypt, passwordFieldStart);

                try
                {
                    // Try to decrypt the chunk
                    byte[] unprotectedPassword = ProtectedData.Unprotect(passwordBlob, null, DataProtectionScope.LocalMachine);

                    // Strip any null bytes that were added
                    for(int i=0; i<unprotectedPassword.Length; ++i)
                    {
                        if(unprotectedPassword[i] == 0x00)
                        {
                            unprotectedPassword = Slice(unprotectedPassword, 0, i);
                            break;
                        }
                    }

                    // Store the password
                    theStore.password = Encoding.ASCII.GetString(unprotectedPassword);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to decrypt password --- This needs to be run as the user who owns the password");
                    // failure
                }
            }
            else
            {
                // Ok, we failed to find an encrypted blob, maybe it's not encrypted?
                //searchForPassword = { 0x03, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01 };

                Console.WriteLine("Failed to find an encrypted password blob :/");
            }
            
            return theStore;
        }

        // This function decrypts a standard WPA2 PSK password
        // Current unused
        // Needs to be run as SYSTEM
        public static string DecryptWirelessPassword(string encodedPassword)
        {
            try
            {
                // Convert to a byte array
                byte[] passwordBytes = new byte[encodedPassword.Length / 2];
                for (int i = 0; i < encodedPassword.Length; i += 2)
                    passwordBytes[i / 2] = Convert.ToByte(encodedPassword.Substring(i, 2), 16);

                // Decode the data and return it
                byte[] unprotectedBytes = ProtectedData.Unprotect(passwordBytes, null, DataProtectionScope.LocalMachine);
                return Encoding.ASCII.GetString(unprotectedBytes);
            }
            catch (Exception e)
            {
                Console.WriteLine("decrypting wifi password failed! " + e.Message);
                return null;
            }
        }
    }
}
