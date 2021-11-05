# "404 Not Found" Cell Pattern

Build the Docker containers `ubuntu-shadow-tgen-tor-cellcounters` and `ubuntu-tornetgen-tor` that we use to prepare and run our Shadow experiments regarding the cell pattern characteristics:
```bash
user@host  $    cd docker-builds
user@host  $    sudo docker build -t ubuntu-shadow-tgen-tor-cellcounters -f Dockerfile.shadow .
user@host  $    sudo docker build -t ubuntu-tornetgen-tor -f Dockerfile.tornetgen .
```
We fix the versions of the major software components to specific git commits for reproducibility, please check the Dockerfiles to find the specific commits.


### Determinism

Please see the contained [`README.md`](./determinism/README.md) file for information regarding the determinism experiments.


### Uniqueness

Please see the contained [`README.md`](./uniqueness/README.md) file for information regarding the uniqueness experiments.
