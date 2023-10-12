const mysql = require("mysql");


// Create a connection pool
const connection = mysql.createPool({

  host: "localhost", // Your MySQL host
  user: "root", // Your MySQL username
  password: "", // Your MySQL password
  database: "Emp_sql", // Your database name
});

// Test the connection
connection.getConnection((err, conn) => {
  if (err) {
    console.error("Database connection failed: " + err.message);
  } else {
    console.log("Connected to the database");
    conn.release();
  }
});

module.exports = connection;



// const mysql = require('mysql');

// const con = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "",
//   database:"Emp_sql"
// });


// con.connect(function(err) {
//   if (err) throw err;
//   console.log("Connected to database");
//   // con.query("CREATE DATABASE Emp_sql", function (err, result) {
//   //   if (err) throw err;
//   //   console.log("Database created");
//   // });
// });