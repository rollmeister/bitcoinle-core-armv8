The following should install all required libraries to run BLE Core...  
sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils software-properties-common libboost-all-dev  
sudo add-apt-repository ppa:bitcoin/bitcoin  
sudo apt-get update  
sudo apt-get install libdb4.8-dev libdb4.8++-dev  

Download using  
wget https://github.com/rollmeister/bitcoinle-core-armv8/raw/master/binaries/bitcoinle-core-armv8-binaries.tar.gz --no-check-certificate  

extract with   
tar xvzf bitcoinle-core-armv8-binaries.tar.gz  
Built on Ubuntu 16.04. May work on other Linux distributions if required libraries are installed.  
Sources are released before Christmas, after I return from holidays.
