const express = require("express");
const router = express.Router();
const admindata = require("../controller/admin/AdminController")
const useraccess = require("../controller/admin/UserManegment")
const connection = require("../config/Db.config");
const CommonService = require("../services/CommonService")
const EmailService = require("../services/EmailService")
// const uploadFile = require("../middleware/FileUpload")


const {adminauthenticationToken} = require("../middleware/auth")

//Admin Routes
router.post("/signup",  admindata.AdminSingup);
router.post("/signin",  admindata.AdminSingIn);
router.patch("/update", adminauthenticationToken,admindata.Updateadmin)
router.patch("/changepassword",  adminauthenticationToken,admindata.Adminchangepassword);
router.post("/singout", adminauthenticationToken,admindata.Adminlogout);

//admin forgot password
 router.post("/adminsentotp",  EmailService.sentotp);
 router.post("/adminverifyotp",  EmailService.verifyOTP);
 router.post("/adminresetPassword",  EmailService.resetPassword);


//User Routes
router.post("/usersingup",  adminauthenticationToken,useraccess.SignUp);
router.get("/userfind", adminauthenticationToken,useraccess.UserFind);
router.get("/alluser", adminauthenticationToken,useraccess.UserFindAll);
router.delete("/userdelete", adminauthenticationToken,useraccess.UserDelete);
router.delete("/userHarddelete", adminauthenticationToken,useraccess.UserDeleteAccount);
router.patch("/userupdate", adminauthenticationToken,useraccess.UserUpdate,);
router.patch("/useractive", adminauthenticationToken,useraccess.userActive);

module.exports = router;