const bcrypt = require("bcrypt");
// const { model } = require("mongoose");
// const EmpRegister = require("../models/User");
// const adminuser = require("../models/Admin");
const responsemessage = require("../utils/ResponseMessage.json");
// const connection = require("../config/Db.config");
const { StatusCodes } = require("http-status-codes");

async function passwordencrypt(password) {
  let salt = await bcrypt.genSalt(10);
  let passwordHash = bcrypt.hash(password, salt);
  return passwordHash;
}

function validatePassword(password) {
  const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$&%])(?!.*\s).{6,16}$/;
  return pattern.test(password);
}






module.exports = { passwordencrypt,validatePassword };
