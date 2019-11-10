UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make
cd ./unicorn_mode
./build_unicorn_support.sh
cd ..
cd hal_fuzz
pip3 install -r ../requirements.txt
pip3 install -e .
cd hal_fuzz/native
make
cd ../../../
cd unicorn_mode/unicorn-1.0.1/bindings/python
python3 setup.py install
cd ../../../../
