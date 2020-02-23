#./config-run.sh

sudo rm -rf test/output/ 
mkdir test/output/

rm -r build
mkdir build
cd build
#make clean
cmake ../ -DPREFIX=. -DBUILD_TYPE="Release"
make
make install 

python ./bin/ptfuzzer.py  "-i ../test/input/ -o ../test/output -X ../test/targets.txt" "../test/a.out"

#python ./bin/run_with_pt.py ../test/a.out file

#python ./bin/run_with_pt.py ../ocean-non_contiguous_partitions/OCEAN