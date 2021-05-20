use user-database-name
db.createUser(
    {
        user: "username",
        pwd: passwordPrompt(),
        roles: [ { role: "readWrite", db: "user-database-name" } ]
    }
)