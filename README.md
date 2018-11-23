Git newbies, how to to install repo sources into a folder. Refer to docs/build-unix.md for other software dependencies install.  
```
sudo apt install git
git clone https://github.com/rollmeister/bitcoinle-core-armv8.git #replace_with_optional_custom_folder_name
cd bitcoinle-core-armv8 #default folder repo is cloned into
```
Pre-compiled available in binaries folder, might work for you. Otherwise...  
Compiling requires (see also choice of compiler before this step)  
```
chmod x+u autogen.sh #only need to do this line once
./autogen.sh
./configure --disable-tests --disable-bench  
make
```
###### Choice of compiler.
GCC8.1 is available for 64-bit Ubuntu 16.04 on aarch64(ArmV8). Slowest compile but fastest binaries. Requires 1gb both ram and swap memory.  
```
sudo add-apt-repository ppa:ubuntu-toolchain-r/test 
sudo add-apt-repository ppa:jonathonf/gcc  
sudo apt update
sudo install gcc-8 g++-8
```
Alternatively Clang 6.0, faster compile less memory requirements. Can compile with make -j 2 on 1gb boards, with a swap file.
```
sudo apt install clang-6.0
```

bitcoinle-miner may crash. Use a bash script to restart it...
```
until ~/PATHTOBINARY/./bitcoinle-miner > bitcoinleminer.log; do  
    echo "Server 'myserver' crashed with exit code $?.  Respawning.." >&2  
    sleep 10  
done  
```
There is a slow memory leak in the software so restarting say using a cron job once a week is recommended.  

This is a fork of the BitcoinLE Core software optimised for ArmV8. Hashrates on a 1.8ghz Cortex-a53 cpu core is 800kh/sec. 500-1000% improvements to hashrates are foreseen. Keep checking repo for updates.  

BitcoinLE Core (BLE) requires Bitcoin (BTC) Core running separately as a Metronome.
You do not need an established Bitcoin Wallet with balance to run Bitcoin Core.

bitcoinle-miner (for solo mining) also works as a BitcoinLE wallet.

Pruned Bitcoin Blockchain. Suitable for running a Bitcoin Wallet as a Metronome for the solo miner. Takes hours, instead of weeks to sync. Date of archive sync 13-11-2018. Less than 3gb download.  
https://drive.google.com/open?id=1N35z4iKCwD4rcrCvZ8IV5F8VpQ0kj6M4

Extract on Linux using...  
```
tar xvjf prunedbtcblockchain.tar.bz2 ~/.bitcoin  
```
(goes into bitcoin core app folder)  

###### Add this to bitcoin.conf (of your bitcoin (NOT bitcoinle) app data folder)  
```
prune=550  
checklevel=2  
checkblocks=10  
checkblocksverify=10  
listen=1  
dbcache=256  
rpcport=8332  
upnp=0  
rpcuser=YOURMETRONOMEusername  
rpcpassword=YOURMETRONOMEpassword  
rpcallowip=0.0.0.0/0  
#OR allow only lan connections. e.g. IP class 192.168.10 (the first three numbers of your lan ip address)  
#rpcallowip=192.168.10/24  
server=1  
```
###### Add Metronome details for BitcoinLE Core ArmV8 into .bitcoinle/bitcoin.conf  
```
metronomeAddr=xxx.xxx.xxx.xxx  
metronomePort=8332  
metronomeUser=YOURMETRONOMEusername  
metronomePassword=YOURMETRONOMEpassword  
upnp=1  
addnode=seed1.bitcoinle.org  
addnode=seed2.bitcoinle.org  
addnode=seed3.bitcoinle.org  
```
###### Bitcoin Core (e.g. for use as a Metronome) optimised fork  
Binary downloads also available for aarch64/Ubuntu 16.04  
https://github.com/rollmeister/bitcoin-armv8  

Bitcoin LE Core integration/staging tree
=====================================

https://bitcoinle.org

What is Bitcoin LE?
----------------

Bitcoin LE is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Bitcoin LE uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Bitcoin LE inherits most of its features from Bitcoin but introduces a new Proof of Work algorithm that drastically reduces the carbon footprint of mining activities. Bitcoin LE Core is the name of the open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Bitcoin LE Core software, see [here](../../releases), or read the
[original whitepaper](whitepaper/README.md).

License
-------

Bitcoin LE Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Documentation
------------

Original documentation inherited from Bitcoin can be found in the [doc](doc) folder.
Bitcoin LE specific documentation can be found in the [doc-le](doc-le) folder. There you can find more information about how to connect to the metronome or how to use Bitcoin LE reference miner.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](../../releases) are created
regularly to indicate new official, stable release versions of Bitcoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

The developer mailing list should be used to discuss complicated or controversial changes before working
on a patch set.
