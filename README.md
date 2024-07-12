# Extract-MKeys-from-Bitcoin-Wallets
Extract MKeys from Bitcoin Wallets
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

Install Requirements
sh
Copy code
pip install -r requirements.txt
Additional Requirements for rarfile
For rarfile to work properly, you need to have unrar installed on your system. On Debian/Ubuntu-based systems, you can install it using:

sh
Copy code
sudo apt-get install unrar
Usage
Clone this repository or download the script.
Open a terminal and navigate to the directory containing the script.
Run the script using the following command:
sh
Copy code
python extract_mkeys.py out.txt
Replace out.txt with the desired name for your output file.

Example Output
The output file will contain detailed information about each processed file, for example:

makefile
Copy code
/path/to/file.dat:
mkey_encrypted: ...
target_mkey: ...
ct: ...
salt: ...
iv: ...
rawi: ...
iter: ...

/path/to/anotherfile.dat:
mkey_encrypted: ...
target_mkey: ...
ct: ...
salt: ...
iv: ...
rawi: ...
iter: ...
License
This project is licensed under the MIT License - see the LICENSE file for details.

Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an Issue for any bugs or feature requests.
