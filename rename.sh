i=16
for file in *.c
do
    mv -i "${file}" "test${i}.c"
    i=$((i+1));
done

i=16
for file in *.json
do
    mv -i "${file}" "test${i}.json"
    echo ${file}
    i=$((i+1));
done

i=16
for file in *.assembly
do
    mv -i "${file}" "test${i}.assembly"
    i=$((i+1));
done
i=16
for file in *.o
do
    mv -i "${file}" "test${i}.o"
    i=$((i+1));
done

