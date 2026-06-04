FROM rust:1.89

WORKDIR /usr/src/myapp
COPY . .

RUN ["cargo", "build", "--release"]

ENTRYPOINT [ "cargo", "run", "--release", "--"]
CMD ["tutor"]
