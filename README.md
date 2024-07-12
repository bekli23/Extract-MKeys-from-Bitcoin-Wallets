Extract MKeys from Bitcoin Wallets
This Python script automates the extraction of master keys (mkey) from Bitcoin Core wallet files (.dat) and archives (.zip, .rar, .7z). It recursively searches the current directory and its subdirectories for these files, processes them, and logs the extracted information into a specified output file.

Features
Recursively search for .dat files in the current directory and subdirectories.
Extract .dat files from supported archives (.zip, .rar, .7z) smaller than 5 MB.
Extract detailed master key information from each .dat file.
Log extracted information, including mkey_encrypted, target_mkey, ct, salt, iv, rawi, and iter values, to an output file.
Display a real-time progress bar with information on the current file, directory, and processing speed.
Requirements
To run this script, you need to have Python and the required libraries installed. The necessary libraries are listed in the requirements.txt file.

