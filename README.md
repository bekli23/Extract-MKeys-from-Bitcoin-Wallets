# Wallet Information Extractor

This Python script extracts all Bitcoin public keys, encrypted private keys (ckey), and other relevant information from a `wallet.dat` file and saves them into a specified text file.

## Features

- Extracts Bitcoin public keys and their corresponding Bitcoin addresses.
- Extracts encrypted private keys (ckey).
- Extracts and displays detailed information about the master key (`mkey`).
- Saves all extracted information into a specified text file.

## Requirements

- Python 3.x
- `bsddb3` library
- `pycryptodome` library
- `base58` library

## Installation

1. Clone this repository:

    ```bash
    git clone bekli23/Extract-MKeys-from-Bitcoin-Wallets.git
    cd wallet-info-extractor
    ```

2. Install the required libraries:

    ```bash
    pip install bsddb3 pycryptodome base58
    ```

## Usage

To run the script and extract information from a `wallet.dat` file, use the following command:

```bash
python get_all_info_dat.py <wallet.dat> <output.txt>
This command will extract all relevant information from wallet.dat and save it into output.txt.

Output
The script will generate an output file containing:

Master key information (mkey):
Encrypted master key
Target master key
Ciphertext (CT)
Salt
Initialization Vector (IV)
Raw iteration count
Iteration count
Encrypted private keys (ckey)
Public keys
Bitcoin addresses
Sample Output

********************************************************
*                                      *
* Acest script este privat. Strict interzis pentru public *
********************************************************

Mkey_encrypted: 5da2bc22cf0b5b16f457e88b49af4240383b24d1a5f1643d81a4a98524f75a861448dc51dac2a2d917f71e34e5a2f6b5
Target mkey  : 5da2bc22cf0b5b16f457e88b49af4240383b24d1a5f1643d81a4a98524f75a861448dc51dac2a2d917f71e34e5a2f6b51e26056be20cf38b00047517
CT           : 1448dc51dac2a2d917f71e34e5a2f6b5
Salt         : 1e26056be20cf38b
IV           : 383b24d1a5f1643d81a4a98524f75a86
Raw Iter     : 00047517
Iterations   : 292119

Encrypted ckey: ...
Public key    : ...
Public address: ...

===== Wallet Key Stats =====
...
License
This project is licensed under the MIT License - see the LICENSE file for details.

Old version v1.2
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

