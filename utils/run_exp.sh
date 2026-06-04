
# table 4: e2e
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 4096 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-4k.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-100k.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 2097152 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-2m.csv

docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 4096 100 1 
mv shared/results/bench_crypto.csv shared/results/bench_crypto-4k.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 102400 100 1 
mv shared/results/bench_crypto.csv shared/results/bench_crypto-100k.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-crypto 2097152 100 1 
mv shared/results/bench_crypto.csv shared/results/bench_crypto-2m.csv

#############
# tab 5: bundle sizes
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-bundle

#############
# tab 6: Configured Robot/User overhead
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 1 1 100 1 
mv shared/results/e2e.csv shared/results/e2e-100k-1-1.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 1 5 100 1 
mv shared/results/e2e.csv shared/results/e2e-100k-1-5.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 5 5 100 1 
mv shared/results/e2e.csv shared/results/e2e-100k-5-5.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 5 10 100 1
mv shared/results/e2e.csv shared/results/e2e-100k-5-10.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 10 10 100 1
mv shared/results/e2e.csv shared/results/e2e-100k-10-10.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 10 20 100 1
mv shared/results/e2e.csv shared/results/e2e-100k-10-20.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra e2e 102400 20 20 100 1
mv shared/results/e2e.csv shared/results/e2e-100k-20-20.csv

#############
# tab 7: Sensitivity to policy complexity. 
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-policy 100 1

#############
# Table 8: Refresh overhead
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra rotate 100 4096
mv shared/results/rotate.csv shared/results/rotate-4k.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra rotate 100 102400
mv shared/results/rotate.csv shared/results/rotate-100k.csv
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra rotate 100 2097152
mv shared/results/rotate.csv shared/results/rotate-2m.csv

#############
# Table 9: Affected-bundle refresh scaling for a fixed 2MB payload
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra rotate 100 2097152

#############
# Table 10: User-key re-issuance cost for affected Users
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-keyissue 4

###########
# Table 11 and 12: Attacks
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra attack-replay
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra attack-mtls
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra attack-policy

###########
# Table 11: audit overhead
docker run -v ./shared:/usr/src/myapp/shared -it --rm ssra bench-audit 1000000