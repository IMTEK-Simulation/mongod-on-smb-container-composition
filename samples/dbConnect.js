// This js snippet can test the connectivity to the main mongodb service
// from within a running mongo-express container for debugging purposes.
// Drop into shell with `docker-compose run mongo-express bash`,
// create a file with this content and run with `node dbConnect.js`.
var fs = require('fs');
var CAFileBuf = fs.readFileSync('/run/secrets/tls_CA.pem');
var certFileBuf = fs.readFileSync('/run/secrets/tls_cert.pem');
var keyFileBuf = fs.readFileSync('/run/secrets/tls_key.pem');
var mongoUrl = 'mongodb://admin:admin@mongodb:27017/admin?ssl=true';
var options = {
  ssl: true,
  sslValidate: true,
  sslCA: CAFileBuf,
  sslCert: certFileBuf,
  sslKey: keyFileBuf,
};
var MongoClient = require('mongodb').MongoClient
  , assert = require('assert');

MongoClient.connect(mongoUrl, options, function(err, db) {
   assert.equal(null, err);
   console.log("Connected correctly to server");
   db.close();
 });
