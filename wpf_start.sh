#./config-run.sh

sudo rm -rf test/output/ 
mkdir test/output/

rm -f pscore_trace.txt
rm -f pscore.txt
rm -f execution_path.txt
rm -f execution_path2.txt

sudo rm -r build
mkdir build
cd build
#make clean
cmake ../ -DPREFIX=. -DBUILD_TYPE="Debug"
make
make install 

#python ./bin/ptfuzzer.py  "-i ../test/input/ -o ../test/output -X ../test/targets.txt" "../test/a.out"

#python ./bin/ptfuzzer.py  "-i ../binutils/input/ -o ../binutils/output/ -X ../binutils/targets.txt" "../binutils/cxxfilt"
#python ./bin/ptfuzzer.py  "-i ../test/input/ -o ../test/output" "../test/a.out"

#python ./bin/run_with_pt.py ../test/a.out file
python ./bin/run_with_pt.py ../binutils/cxxfilt

#python ./bin/run_with_pt.py ../ocean-non_contiguous_partitions/OCEAN