Compiling requires  
./configure --disable-tests --disable-bench  
for configure step

bitcoinle-miner will crash. Used a bash script to restart it...

until ~/PATHTOBINARY/./bitcoinle-miner > bitcoinleminer.log; do
    echo "Server 'myserver' crashed with exit code $?.  Respawning.." >&2
    sleep 10
done

This is a fork of the BitcoinLE Core software optimised for ArmV8. Hashrates on a 1.8ghz Cortex-a53 cpu core is 800kh/sec.

BitcoinLE Core (BLE) requires Bitcoin (BTC) Core running separately as a Metronome.
You do not need an established Bitcoin Wallet with balance to run Bitcoin Core.

bitcoinle-miner (for solo mining) also works as a BitcoinLE wallet.

DOWNLOAD THE SOLO MINING ON ARMV8 STARTUP GUIDE FROM...

https://drive.google.com/open?id=1KfOKRjyN9sCnnhtu8SuBkitJqZdHraIA

Pruned Bitcoin Blockchain. Suitable for running a Bitcoin Wallet as a Metronome for the solo miner. Takes hours, instead of weeks to sync. Date of archive sync 13-11-2018. Less than 3gb download.  
https://drive.google.com/open?id=1N35z4iKCwD4rcrCvZ8IV5F8VpQ0kj6M4

Extract on Linux using...  
tar xvjf prunedbtcblockchain.tar.bz2 ~/.bitcoin  
(goes into bitcoin core app folder)  

# Add this to bitcoin.conf (of your bitcoin (NOT bitcoinle) app data folder)  
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

# Add Metronome details for BitcoinLE Core ArmV8 into .bitcoinle/bitcoin.conf  
metronomeAddr=xxx.xxx.xxx.xxx  
metronomePort=8332  
metronomeUser=YOURMETRONOMEusername  
metronomePassword=YOURMETRONOMEpassword  
upnp=1  
addnode=seed1.bitcoinle.org  
addnode=seed2.bitcoinle.org  
addnode=seed3.bitcoinle.org  

# Bitcoin Core (e.g. for use as a Metronome) optimised fork  
Binary downloads available for aarch64/Ubuntu 16.04  
https://github.com/rollmeister/bitcoin-armv8  

During solo minig, when the bitcoinle-miner receives a beat from the Metronome it mines for up to 45 seconds, unless it finds a valid block before. Previously the miner stopped as soon it detected a block was already mined by someone else, however this had a bug that caused a segfault and so a fixed mining period was set as a work around.  
This is still alpha software.

There is a slow memory leak in the software so restarting say using a cron job once a week is recommended.

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
