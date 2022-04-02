This is an LD_PRELOAD shim to intercept networking API calls and bind sockets to source address.

To build:

```
# install gcc if not already installed
sudo apt-get update
sudo apt-get install gcc

# create target folder and upload source
mkdir ~/forceIP
pushd ~/forceIP
rm forceIP.c
wget https://raw.githubusercontent.com/tool-maker/forceIP/main/forceIP.c
ls -la

# compile it
gcc -nostartfiles -fpic -shared forceIP.c -o forceIP.so -ldl
ls -la

# leave target folder
popd
```
