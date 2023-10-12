const express = require("express");
const router = express.Router();
const EmpRegister = require("../controller/user/UserController")
const CommonService = require("../services/CommonService")
const {UserValidateToken} = require("../middleware/auth")
const uploadFile = require("../middleware/FileUpload")
const mysql = require("mysql")


router.post("/signup",EmpRegister.SignUp);
router.post("/signin", EmpRegister.SignIn);
router.get("/viewdata", UserValidateToken,EmpRegister.UserFind);
router.delete("/userdelete", UserValidateToken,EmpRegister.UserDelete);
router.delete("/userdeleteaccount", UserValidateToken,EmpRegister.UserDeleteAccount);
// router.patch("/userupdate", UserValidateToken,uploadFile,EmpRegister.UserUpdate);
// router.post("/forgotpassword", EmpRegister.ForgotPassword);
// router.post("/sendotp", EmpRegister.SendOTP);
// router.post("/verifyotp", CommonService.VerifyOTP);
router.patch("/ChangePassword", UserValidateToken,EmpRegister.ChangePassword);
router.post("/logout", UserValidateToken,EmpRegister.UserLogout);


module.exports = router;