const express = require("express");
const router = express.Router();
const EmpRegister = require("../controller/user/UserController")
const CommonService = require("../services/CommonService")
const {UserValidateToken} = require("../middleware/auth")
const uploadFile = require("../middleware/FileUpload")
const mysql = require("mysql")
const EmailService = require("../services/EmailService")

router.post("/signup",EmpRegister.SignUp);
router.post("/signin", EmpRegister.SignIn);
router.get("/viewdata", UserValidateToken,EmpRegister.UserFind);
router.delete("/userdelete", UserValidateToken,EmpRegister.UserDelete);
router.delete("/userdeleteaccount", UserValidateToken,EmpRegister.UserDeleteAccount);
router.patch("/userupdate", UserValidateToken,EmpRegister.UserUpdate);
router.patch("/ChangePassword", UserValidateToken,EmpRegister.ChangePassword);
router.post("/logout", UserValidateToken,EmpRegister.UserLogout);


 router.post("/sendotp", EmailService.sentotp);
 router.post("/verifyotp", EmailService.verifyOTP);
 router.post("/resetPassword", EmailService.resetPassword);
 
 
module.exports = router;