# IMTEK Simulation MongoDB

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/IMTEK-Simulation/mongod-on-smb-container-composition/test)](https://github.com/IMTEK-Simulation/mongod-on-smb-container-composition/actions?query=workflow%3Atest)

Copyright 2021, IMTEK Simulation, University of Freiburg

Author: Johannes Hoermann, johannes.hoermann@imtek.uni-freiburg.de

## Introduction

This container composition provides a mongodb server and a backup service
both operaing on independent smb shares. It serves as testing framework
and template for provision. Components are

* [imteksim/mongodb-on-smb on dockerhub](https://hub.docker.com/r/imteksim/mongod-on-smb), [on github](https://github.com/IMTEK-Simulation/mongod-on-smb-container-image)
* [imteksim/mongodb-backup on dockerhub](https://hub.docker.com/r/imteksim/mongodb-backup), [on github](https://github.com/IMTEK-Simulation/mongodb-backup-container-image)
* [https://hub.docker.com/r/dperson/samba

## Secrets

Use `bash generate_root_ca.sh`, `bash generate_derived_certs.sh`, and
`bash copy.sh ../secrets`  within this repository's `keys` subdirectory to
generate all required `*.pem' keys and self-signed certificates and place them
within the `secrets` subdirectory for testing purpose.
`tls_key_cert.pem` files are just concatenated `tls_key.pem` and `tls_cert.pem`
files. For convenience, both split and combined formats are provided
in all cases.

The following sensitive data must be provided via secrets:

* `secrets/mongodb/smb-credentials`
* `secrets/mongodb_backup/smb-credentials`
* `secrets/mongodb/username`
* `secrets/mongodb/password`
* `secrets/mongodb/tls_key.pem`
* `secrets/mongodb/tls_cert.pem`
* `secrets/mongodb/tls_key_cert.pem`
* `secrets/mongodb_backup/tls_key.pem`
* `secrets/mongodb_backup/tls_cert.pem`
* `secrets/mongodb_backup/tls_key_cert.pem`
* `secrets/rootCA.pem`


## Open issues

Won't create ready-to-use db smoothly without user interference.
TODO: Integrate the following manual fix into entry point at first launch on nonexistant db.

If the pod is launched on an empty database directory (i.e. the default `/mnt/db`),
then a new databse is created. In order to provide continuous oplog backups,
the standard configuration has mongodb's replica set mechanism (with only
a single primary and no secondaries) activated. Otherwise, mongod won't write
oplog.

Adapt snippet `init_rs.js` (part of `mongod_backup`) to match used host and port.

Enter the freshly running `mongodb` container, i.e. via

    docker exec -it mongodb bash

enter the mongo shell with

    mongo --tls --tlsCAFile /run/secrets/rootCA.pem --tlsCertificateKeyFile \
        /run/secrets/tls_key_cert.pem --host mongodb

and run the adapted `init_rs.js` snippet, i.e.

    > rs.initiate( {
       _id : "rs0",
       members: [
          { _id: 0, host: "simdata.vm.uni-freiburg.de:27017" },
       ]
    })
    { "ok" : 1 }
    rs0:SECONDARY> exit

Note that the prompt changes from `>` to `rs0:SECONDARY>`.
Now, on relogin into the mongo shell, the prompt should read

    rs0:PRIMARY>

and we create the admin user manually with

    rs0:PRIMARY> use admin
    rs0:PRIMARY> db.createUser({
    ...     user: "admin",
    ...     pwd: passwordPrompt(),
    ...     roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
    ...     }
    ... )
    Enter password: 
    Successfully added user: {
        "user" : "admin",
        "roles" : [
            {
                "role" : "userAdminAnyDatabase",
                "db" : "admin"
            },
            "readWriteAnyDatabase"
        ]
    }


and a password in accord with what was provided via `/run/secrets/mongodb/password`.
Eventually, exit and restart the mongodb container (or the whole pod).


### Debugging

Note: Bringing up the db on an smb share might take time. The
`mongo-express` service will fail several times before succeeding to
connect to the `mongod`service.

Look at the database at `https://localhost:8081` or try to connect to the database
from within the mongo container with

    mongo --tls --tlsCAFile /run/secrets/rootCA.pem --tlsCertificateKeyFile \
        /run/secrets/tls_key_cert.pem --host mongodb

or from the host system

     mongo --tls --tlsCAFile keys/rootCA.pem \
        --tlsCertificateKeyFile keys/mongodb.pem --sslAllowInvalidHostnames

if the FQDN in the server's certificate has been set to the service's name 
'mongodb'.

### Wipe database

Enter a running `mongodb` container instance, i.e. with

    docker exec -it mongodb bash

find `mongod`'s pid, i.e. with 

```console
$
...
mongodb     41  0.3  1.4 1580536 112584 ?      SLl  13:06   0:06 mongod --config /etc/mongod.conf --auth --bind_ip_all
...
```
end it, i.e. with `kill 41`, to release all database files, and purge the database directory with

    rm -rf /data/db/*


### Restore database

For a full restore with oplog replay, create the role

    db.createRole(
        {
            role: "anyActionOnAnyResource",
            privileges: [
                { resource: { anyResource: true }, actions: ['anyAction'] },
            ],
            roles: []
        }
    )

and grant it to the `admin` user via

    db.grantRolesToUser("admin", ["anyActionOnAnyResource"])

before running the `mongodb-backup`'s `full_restore.sh`.


### Repair database

If the database got corrupted and mongod won't launch anymore, stop all pods and containers and prune with

    docker container prune

then run a repair instance once, i.e. with

    docker run -d --name=mongodb --security-opt label=disable \
        -e MONGO_INITDB_ROOT_USERNAME_FILE=/run/secrets/mongodb/username -e MONGO_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongodb/password \
        -e TZ=Europe/Berlin -v /mnt/db:/data/db --add-host mongodb:127.0.0.1 --restart no mongod-on-smb --repair --config /etc/mongod.conf

Next, we will have to reinitialize the replication set. Prune the previous container again and a standalone instance with

    docker run -d --name=mongodb --security-opt label=disable \
        -e MONGO_INITDB_ROOT_USERNAME_FILE=/run/secrets/mongodb/username -e MONGO_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongodb/password \
        -e TZ=Europe/Berlin -v /mnt/db:/data/db --restart no \
        mongod-on-smb --auth --tlsMode requireTLS --tlsCertificateKeyFile /run/secrets/mongodb/tls_key_cert.pem --tlsCAFile /run/secrets/rootCA.pem

All configuration options happen on the command line to render the `repSet` options within the config file inneffective. 
Enter the mongo shell on the running instance, i.e. with

    docker exec -it mongodb \
        mongo --tls --tlsCAFile /run/secrets/rootCA.pem --tlsCertificateKeyFile \
        /run/secrets/mongodb/tls_key_cert.pem --host mongodb

and, as above, grant the `anyActionOnAnyResource` role to the admin user. Drop the `local` database with

    use local
    db.dropDatabase()

and start as usual, i.e. with

    docker-compose up -d

to reactivate the replica set with

    rs.initiate( {
       _id : "rs0",
       members: [
          { _id: 0, host: "simdata.vm.uni-freiburg.de:27017" },
       ]
    })

after identifying as admin within the mongos shell. Restart with 

    docker-compose restart mongodb

and confirm that the mongo prompt reads

    rs0:PRIMARY>

again.

(https://medium.com/@cjandsilvap/from-a-replica-set-to-a-standalone-mongodb-79fda2beaaaf)


## References

- Certificates:
  - https://medium.com/@rajanmaharjan/secure-your-mongodb-connections-ssl-tls-92e2addb3c89
- Docker setup
  - Mounting samba share in docker container:
    - https://github.com/moby/moby/issues/22197
    - https://stackoverflow.com/questions/27989751/mount-smb-cifs-share-within-a-docker-container
  - Sensitive data:
    - https://docs.docker.com/compose/compose-file/#secrets
    - https://docs.docker.com/compose/compose-file/#secrets-configuration-reference
  - MongoDB, mongo-express & docker:
    - https://hub.docker.com/_/mongo
    - https://docs.mongodb.com/manual/administration/security-checklist/
    - https://docs.mongodb.com/manual/tutorial/configure-ssl
    - https://hub.docker.com/_/mongo-express
    - https://github.com/mongo-express/mongo-express
    - https://github.com/mongo-express/mongo-express/blob/e4777b6f8bce62d204e9c4204801e2cb7a7b8898/config.default.js#L41
    - https://github.com/mongo-express/mongo-express-docker
    - https://github.com/mongo-express/mongo-express/pull/574
- Related configurations:
  - https://github.com/pastewka/dtool_lookup_docker

## Issues

### MongoDB warnings

mongod warns about

```
** WARNING: /sys/kernel/mm/transparent_hugepage/enabled is 'always'.
**        We suggest setting it to 'never'
```

at startup, see https://docs.mongodb.com/manual/tutorial/transparent-huge-pages/.
THP (Transparent HugePages) would have to be disabled at host boot. 
