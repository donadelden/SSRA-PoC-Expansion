# table 4: e2e
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 4096 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-4k-rpi.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-100k-rpi.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 2097152 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-2m-rpi.csv

docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 4096 100 1 
mv shared/results/bench_crypto.csv shared/results/bench_crypto-4k-rpi.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 102400 100 1 
mv shared/results/bench_crypto.csv shared/results/bench_crypto-100k-rpi.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 2097152 100 1 
mv shared/results/bench_crypto.csv shared/results/bench_crypto-2m-rpi.csv