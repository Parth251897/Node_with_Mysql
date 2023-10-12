const express = require("express");
const mysql = require("mysql")

const bodyParser = require("body-parser");
const cors = require("cors")

require("dotenv").config();
const PORT = 5000;


const db = require("./src/config/Db.config")
const userRoutes = require("./src/routes/UserRoutes")
const adminRoutes = require("./src/routes/AdminRoutes")



const app = express();


app.use(cors())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));



 app.use("/company",userRoutes,);
 app.use("/admin",adminRoutes);

app.listen(PORT, () =>{
    console.log(`Success runing port no ${PORT}`);
})