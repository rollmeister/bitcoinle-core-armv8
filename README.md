Git newbies, how to to install repo sources into a folder. Refer to docs/build-unix.md for other software dependencies install.  
```
sudo apt install git
git clone https://github.com/rollmeister/bitcoinle-core-armv8.git #replace_with_optional_custom_folder_name
#default folder repo is cloned into
cd bitcoinle-core-armv8  
```
To retrieve the updates to the repo into your clone . cd into repo's folder first...  
```
git pull
```
Pre-compiled available in binaries folder, might work for you. Otherwise...  
Compiling requires (see also choice of compiler before this step)  
```
chmod +x autogen.sh #only need to do this line once
./autogen.sh
./configure --disable-tests --disable-bench --with-gui=no  
make
```
There is no gui wallet support at this moment.
You can retrieve wallet balance and do transfers with command line bitcoinle-cli  
Specify compiler to use with CC & CXX parameters e.g.  
```
chmod x+u autogen.sh #only need to do this line once
./autogen.sh
./configure CC="gcc-8" CXX="g++-8" --disable-tests --disable-bench --with-gui=no  
make CC="gcc-8" CXX="g++-8"
```
###### Optionally strip binary of bloat (less ram consumption)
```
strip src/bitcoinled; strip src/bitcoinle-miner; strip src/bitcoinle-cli; strip src/bitcoinle-tx;
```
###### Choice of compiler.
GCC8.1 is available for 64-bit Ubuntu 16.04 on aarch64(ArmV8). Slowest compile but faster & smaller binaries. Requires 1gb both ram and swap memory. Please consider donating to Jonathan for his good work in making GCC 8.1 available  
https://www.buymeacoffee.com/jonathon
https://paypal.me/jnthnf
```
sudo add-apt-repository ppa:ubuntu-toolchain-r/test 
sudo add-apt-repository ppa:jonathonf/gcc  
sudo apt update
sudo install gcc-8 g++-8
```
Alternatively Clang 6.0, faster compile less memory requirements. Can compile with make -j 2 on 1gb boards, with a swap file.
```
sudo apt install clang-6.0
./configure CC="clang-6.0" CXX="clang++-6.0" --disable-tests --disable-bench
make CC="clang-6.0" CXX="clang++-6.0"
```
bitcoinle-miner may crash. Use a bash code in script to restart it...
```
until ~/PATHTOBINARY/./bitcoinle-miner > bitcoinleminer.log; do  
    echo "Server 'myserver' crashed with exit code $?.  Respawning.." >&2  
    sleep 10  
done  
```
There is a slow memory leak in the software so restarting say using a cron job once a week is recommended.  

This is a fork of the BitcoinLE Core software optimised for ArmV8. Hashrates on a 1.8ghz Cortex-a53 cpu core is 900kh/sec. 500-1000% improvements to hashrates are foreseen. Keep checking repo for updates.  

BitcoinLE Core (BLE) requires Bitcoin (BTC) Core running separately as a Metronome.
You do not need an established Bitcoin Wallet with balance to run Bitcoin Core.

bitcoinle-miner (for solo mining) also works as a BitcoinLE wallet. It is not good practise to use the same wallet.dat for multiple miners. For multiple devices, copy the only the bitcoin.conf file (if you want all solo miners to use same parameters) into .bitcoinLE folder and run bitcoind for 10 minutes on first run, and for everytime you run the solo miner and the BitcoinLE blockchain copy has not been synced for 1 day or more. The bitcoinle-miner has difficulty syncing the BitcoinLE (BLE) blockchain by itself.  
```
./bitcoinled  #for ten minutes  
```
press ctrl+c to exit
```
./bitcoinle-miner # to start solo mining
```
If you experience solo miner crashes, doing a fresh BLE blockchain sync, deleting the .bitcoinLE/blocks and .bitcoinLE/chainstate folders and running bitcoinled for ten minutes may solve it.  

###### Pruned Bitcoin Blockchain.  
Suitable for running a Bitcoin Wallet as a Metronome for the solo miner. Takes hours/days, instead of weeks to sync. Date of current archive sync 13-11-2018. Less than 3gb download but requires 3.5gb free space.  
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
dbcache=4  
rpcport=8332  
upnp=1  
rpcuser=YOURMETRONOMEusername  
rpcpassword=YOURMETRONOMEpassword  
rpcallowip=0.0.0.0/0  
# OR allow only lan connections. e.g. IP class 192.168.10 (the first three numbers of your lan ip address)  
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
listen=1  
dbcache=8  
rpcport=8330  
upnp=1  
rpcuser=YOURCHOSENBLEWalletusername  
rpcpassword=YOURCHOSENBLEWalletpassword  
# Uncomment next line if need rpc connections from internet
#rpcallowip=0.0.0.0/0  
# Allow only lan connections. e.g. IP class 192.168.10 (the first three numbers of your lan ip address)  
rpcallowip=192.168.10/24  
server=1  
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
