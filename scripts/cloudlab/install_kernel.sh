STORAGE_PATH=/users/$USER/disk
sudo apt-get update && sudo apt-get install -y debhelper-compat cmake
sudo mkfs.ext4 /dev/sdb
mkdir $STORAGE_PATH
mount /dev/sdb $STORAGE_PATH
sudo chown $USER $STORAGE_PATH
cd $STORAGE_PATH

git clone https://github.com/acmel/dwarves.git
pushd ./dwarves/
mkdir build/
cd build/
cmake -D__LIB=lib ..
sudo make install
sudo ldconfig

git clone https://github.com/torvalds/linux.git
cd linux
git checkout v6.8-rc7
mkdir build/
cd build/
make -C .. O=$(pwd) defconfig
echo cp /boot/config-$(uname -r) .config
echo yes '' | make oldconfig
echo "Note: disable key-signing for modules and rmeove the keys from .config (disable landlock and module signing)"
echo Configure your kernel and build it
echo make -j 41 bindeb-pkg LOCALVERSION=-my-k

