cargo clean
cd ./rabe
cargo clean
cargo build --release --no-default-features --features borsh
cd ..
cargo build --release