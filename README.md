# IMTEK Simulation MongoDB

Copyright 2021, IMTEK Simulation, University of Freiburg

Author: Johannes Hoermann, johannes.hoermann@imtek.uni-freiburg.de

## Summary

Mount an smb share holding raw db within mongo conatiner and publish
standard port 27017 via TLS/SSL encryption globally.

## Setup with Podman

Podman runs without elevated privileges. The `cifs` driver for smb shares requires
elevated privileges for mount operations. Thus, it must be replaced
by a pure userland approach. The described setup is based on the FUSE
drivers `smbnetfs` and `bindfs`. See `compose/local/mongodb/docker-entrypoint.sh`
for more information.

### Capabilities

Granted capabilities are prefixed by `CAP_`, i.e.

    cap_add:
      - CAP_SYS_ADMIN

for Podman compared to

    cap_add:
      - SYS_ADMIN

for Docker within the `compose.yml` file. This capability in connection with

    devices:
      - /dev/fuse

is necessary for enabling the use of FUSE file system drivers within the unprivileged
container.

### Secrets

podman does not handle `secrets` the way docker does. Similar behavior can be achieved with
a per-user configuration file `$HOME/.config/containers/mounts.conf` on the host containing,
for example, a line

    /home/user/containers/secrets:/run/secrets

that will make the content of `/home/user/containers/secrets` on the host available under
`/run/secrets` within *all containers* of the evoking user. The owner and group within
the container will be `root:root` and file permissions will correspond to permissions
on the host file system. Thus, an entrypoint script might have to adapt permissions.

For this composition, the following secrets must be available:

```
/run/secrets/smbnetfs.auth
/run/secrets/smbnetfs-smbshare-mountpoint
/run/secrets/mongodb/password
/run/secrets/mongodb/username
/run/secrets/mongodb/tls_key.pem
/run/secrets/mongodb/tls_cert.pem
/run/secrets/mongodb/tls_key_cert.pem
/run/secrets/rootCA.pem
```

Use `bash generate.sh` and `bash copy.sh DEST` within this repository's
`keys` subdirectory to generate all required `*.pem' keys and self-signed 
certificates and place them at some desired `DEST` location for testing purpose.
`tls_key_cert.pem` files are just concatenated `tls_key.pem` and `tls_cert.pem`
files. `mongodb` expects them concatenated in one file, while `mongo-express`
needs them separate. For convenience, both split and combined formats are provided 
in all cases. The separate sets of keys an certificates fulfill the following 
purposes:

- `/run/secrets/rootCA.pem` is the certificate chain client's certificates are
  checked against by the `mongodb` service.
- `/run/secrets/mongodb/tls_key_cert.pem` are tsl key and cert used by `mongodb`
  for any communication.
- Keys and certificates within`/run/secrets/mongo_express_inwards` are used internally
  by the `mongo-express` service to communicate with the `mongodb` service.
- Keys and certificates within`/run/secrets/mongo_express_outwards` are used
  by the `mongo-express` service to communicate with outward clients.

Next to keys annd certificates, the following sensitive data must be provided
(and are used by the specified services)

- smb share credentials
  - `/run/secrets/smbnetfs-smbshare-mountpoint`: mongo-on-smb
  - `/run/secrets/smbnetfs.auth`: mongo-on-smb
- mongod admin credentials:
  - `/run/secrets/mongodb/username`: mongo-on-smb, mongo-express
  - `/run/secrets/mongodb/password`: mongo-on-smb, mongo-express
- mongo-express web gui credentials:
  - `/run/secrets/mongo_express/username`: mongo-express
  - `/run/secrets/mongo_express/password`: mongo-express

### podman-compose

As of 2020/05/20, `podman-compose` v 0.1.5 published on PyPi does not support the `devices`
and `restart`options. The current development version of `podman-compose` implements `devices`,
but is broken at
https://github.com/containers/podman-compose/blob/64ed5545437c1348b65b5f9a4298c2212d3d6419/podman_compose.py#L1079

https://github.com/containers/podman-compose/pull/180 implements `restart` and fixes broken code.

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

    podman exec -it mongodb bash

enter the mongo shell with

    mongo --tls --tlsCAFile /run/secrets/rootCA.pem --tlsCertificateKeyFile \
        /run/secrets/mongodb/tls_key_cert.pem --host mongodb

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
        /run/secrets/mongodb/tls_key_cert.pem --host mongodb

or from the host system

     mongo --tls --tlsCAFile keys/rootCA.pem \
        --tlsCertificateKeyFile keys/mongodb.pem --sslAllowInvalidHostnames

if the FQDN in the server's certificate has been set to the service's name 
'mongodb'.

### Wipe database

Enter a running `mongodb` container instance, i.e. with

    podman exec -it mongodb bash

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

    podman container prune

then run a repair instance once, i.e. with

    podman run -d --name=mongodb --security-opt label=disable \
        -e MONGO_INITDB_ROOT_USERNAME_FILE=/run/secrets/mongodb/username -e MONGO_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongodb/password \
        -e TZ=Europe/Berlin -v /mnt/db:/data/db --add-host mongodb:127.0.0.1 --restart no mongod-on-smb --repair --config /etc/mongod.conf

Next, we will have to reinitialize the replication set. Prune the previous container again and a standalone instance with

    podman run -d --name=mongodb --security-opt label=disable \
        -e MONGO_INITDB_ROOT_USERNAME_FILE=/run/secrets/mongodb/username -e MONGO_INITDB_ROOT_PASSWORD_FILE=/run/secrets/mongodb/password \
        -e TZ=Europe/Berlin -v /mnt/db:/data/db --restart no \
        mongod-on-smb --auth --tlsMode requireTLS --tlsCertificateKeyFile /run/secrets/mongodb/tls_key_cert.pem --tlsCAFile /run/secrets/rootCA.pem

All configuration options happen on the command line to render the `repSet` options within the config file inneffective. 
Enter the mongo shell on the running instance, i.e. with

    podman exec -it mongodb \
        mongo --tls --tlsCAFile /run/secrets/rootCA.pem --tlsCertificateKeyFile \
        /run/secrets/mongodb/tls_key_cert.pem --host mongodb

and, as above, grant the `anyActionOnAnyResource` role to the admin user. Drop the `local` database with

    use local
    db.dropDatabase()

and start as usual, i.e. with

    podman-compose up -d

to reactivate the replica set with

    rs.initiate( {
       _id : "rs0",
       members: [
          { _id: 0, host: "simdata.vm.uni-freiburg.de:27017" },
       ]
    })

after identifying as admin within the mongos shell. Restart with 

    podman-compose restart mongodb

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
- Podman setup
  - Sensitive data
    - https://www.projectatomic.io/blog/2018/06/sneak-secrets-into-containers/
  - FUSE-related
    - https://bindfs.org/
    - https://bindfs.org/docs/bindfs-help.txt
    - https://rhodesmill.org/brandon/2010/mounting-windows-shares-in-linux-userspace/
- Related configurations:
  - https://github.com/pastewka/dtool_lookup_docker

## Issues

### Podman-related

Conatiners will usually end with an error like this when shut down:

    ERRO[0243] unable to close namespace: "close /proc/29519/ns/user: bad file descriptor" 

### MongoDB warnings

mongod warns about

```
** WARNING: /sys/kernel/mm/transparent_hugepage/enabled is 'always'.
**        We suggest setting it to 'never'
```

at startup, see https://docs.mongodb.com/manual/tutorial/transparent-huge-pages/.
THP (Transparent HugePages) would have to be disabled at host boot. 

### Unprivileged GVFS
Using `gvfs` and `bindfs` to provide the database, WiredTiger fails:

```
root@5071f576509d:/# cat /data/db/docker-initdb.log
2020-05-21T10:11:01.770+0000 I  CONTROL  [main] Automatically disabling TLS 1.0, to force-enable TLS 1.0 specify --sslDisabledProtocols 'none'
2020-05-21T10:11:01.776+0000 W  ASIO     [main] No TransportLayer configured during NetworkInterface startup
2020-05-21T10:11:01.779+0000 I  CONTROL  [initandlisten] MongoDB starting : pid=139 port=27017 dbpath=/data/db 64-bit host=5071f576509d
2020-05-21T10:11:01.780+0000 I  CONTROL  [initandlisten] db version v4.2.6
2020-05-21T10:11:01.782+0000 I  CONTROL  [initandlisten] git version: 20364840b8f1af16917e4c23c1b5f5efd8b352f8
2020-05-21T10:11:01.783+0000 I  CONTROL  [initandlisten] OpenSSL version: OpenSSL 1.1.1  11 Sep 2018
2020-05-21T10:11:01.785+0000 I  CONTROL  [initandlisten] allocator: tcmalloc
2020-05-21T10:11:01.785+0000 I  CONTROL  [initandlisten] modules: none
2020-05-21T10:11:01.786+0000 I  CONTROL  [initandlisten] build environment:
2020-05-21T10:11:01.787+0000 I  CONTROL  [initandlisten]     distmod: ubuntu1804
2020-05-21T10:11:01.788+0000 I  CONTROL  [initandlisten]     distarch: x86_64
2020-05-21T10:11:01.789+0000 I  CONTROL  [initandlisten]     target_arch: x86_64
2020-05-21T10:11:01.790+0000 I  CONTROL  [initandlisten] options: { config: "/tmp/docker-entrypoint-temp-config.json", net: { bindIp: "127.0.0.1", port: 27017, tls: { mode: "disabled" } }, processManagement: { fork: true, pidFilePath: "/tmp/docker-entrypoint-temp-mongod.pid" }, systemLog: { destination: "file", logAppend: true, path: "/data/db/docker-initdb.log" } }
2020-05-21T10:11:01.849+0000 I  STORAGE  [initandlisten] wiredtiger_open config: create,cache_size=3394M,cache_overflow=(file_max=0M),session_max=33000,eviction=(threads_min=4,threads_max=4),config_base=false,statistics=(fast),log=(enabled=true,archive=true,path=journal,compressor=snappy),file_manager=(close_idle_time=100000,close_scan_interval=10,close_handle_minimum=250),statistics_log=(wait=0),verbose=[recovery_progress,checkpoint_progress],
2020-05-21T10:11:02.611+0000 E  STORAGE  [initandlisten] WiredTiger error (95) [1590055862:611142][139:0x7fe5fe559b00], file:WiredTiger.wt, connection: __posix_open_file, 667: /data/db/WiredTiger.wt: handle-open: open: Operation not supported Raw: [1590055862:611142][139:0x7fe5fe559b00], file:WiredTiger.wt, connection: __posix_open_file, 667: /data/db/WiredTiger.wt: handle-open: open: Operation not supported
2020-05-21T10:11:02.625+0000 E  STORAGE  [initandlisten] WiredTiger error (95) [1590055862:625022][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported Raw: [1590055862:625022][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported
2020-05-21T10:11:02.628+0000 E  STORAGE  [initandlisten] WiredTiger error (95) [1590055862:628694][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported Raw: [1590055862:628694][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported
2020-05-21T10:11:02.632+0000 E  STORAGE  [initandlisten] WiredTiger error (95) [1590055862:632835][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported Raw: [1590055862:632835][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported
2020-05-21T10:11:02.636+0000 E  STORAGE  [initandlisten] WiredTiger error (95) [1590055862:636325][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported Raw: [1590055862:636325][139:0x7fe5fe559b00], wiredtiger_open: __posix_open_file, 667: /data/db/WiredTiger.lock: handle-open: open: Operation not supported
2020-05-21T10:11:02.637+0000 W  STORAGE  [initandlisten] Failed to start up WiredTiger under any compatibility version.
2020-05-21T10:11:02.638+0000 F  STORAGE  [initandlisten] Reason: 95: Operation not supported
2020-05-21T10:11:02.639+0000 F  -        [initandlisten] Fatal Assertion 28595 at src/mongo/db/storage/wiredtiger/wiredtiger_kv_engine.cpp 915
2020-05-21T10:11:02.639+0000 F  -        [initandlisten] 

***aborting after fassert() failure
```

The `__posix_open_file` operation fails at https://github.com/wiredtiger/wiredtiger/blob/8de74488f2bb2b5cba0404c345f568a2f72478d3/src/os_posix/os_fs.c#L661-L667

```C
    WT_SYSCALL_RETRY(((pfh->fd = open(name, f, mode)) == -1 ? -1 : 0), ret);
    if (ret != 0)
        WT_ERR_MSG(session, ret,
          pfh->direct_io ? "%s: handle-open: open: failed with direct I/O configured, "
                           "some filesystem types do not support direct I/O" :
                           "%s: handle-open: open",
          name);
```

Likely, gvfs does not support `direct_io`.
